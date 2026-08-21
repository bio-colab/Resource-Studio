from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


_TOKEN = re.compile(r'\s*(?:(and|or|contains)\b|([A-Za-z_][A-Za-z0-9_.-]*)|(>=|<=|==|!=|>|<)|(\"(?:\\\\.|[^\"\\\\])*\"|\'[^\']*\')|(\d+(?:\.\d+)?)|(\()|(\)))', re.IGNORECASE)
_OPERATORS = {"==", "!=", ">", ">=", "<", "<=", "contains"}
_CONFIDENCE = {"HIGH": 1.0, "MEDIUM": 0.7, "LIMITED": 0.5, "LOW": 0.2, "UNKNOWN": 0.0}


class EvidenceQueryError(ValueError):
    pass


@dataclass(frozen=True)
class _Token:
    kind: str
    value: Any


def tokenize(expression: str) -> tuple[_Token, ...]:
    position = 0
    tokens: list[_Token] = []
    while position < len(expression):
        match = _TOKEN.match(expression, position)
        if not match:
            raise EvidenceQueryError(f"unexpected query text at position {position}")
        keyword, identifier, operator, quoted, number, lparen, rparen = match.groups()
        if keyword:
            tokens.append(_Token(keyword.upper(), keyword))
        elif identifier:
            tokens.append(_Token("IDENT", identifier))
        elif operator:
            tokens.append(_Token("OP", operator))
        elif quoted:
            tokens.append(_Token("VALUE", quoted[1:-1]))
        elif lparen:
            tokens.append(_Token("LPAREN", lparen))
        elif rparen:
            tokens.append(_Token("RPAREN", rparen))
        else:
            tokens.append(_Token("VALUE", float(number) if "." in number else int(number)))
        position = match.end()
    tokens.append(_Token("EOF", None))
    return tuple(tokens)


class _Parser:
    def __init__(self, expression: str) -> None:
        self.tokens = tokenize(expression)
        self.index = 0

    def parse(self):
        tree = self._or_expression()
        self._expect("EOF")
        return tree

    def _or_expression(self):
        node = self._and_expression()
        while self._accept("OR"):
            node = ("or", node, self._and_expression())
        return node

    def _and_expression(self):
        node = self._factor()
        while self._accept("AND"):
            node = ("and", node, self._factor())
        return node

    def _factor(self):
        if self._accept("LPAREN"):
            node = self._or_expression()
            self._expect("RPAREN")
            return node
        field = self._expect("IDENT").value
        operator = self._expect_operator()
        value = self._expect("VALUE").value
        return ("compare", field, operator, value)

    def _expect_operator(self) -> str:
        if self._peek().kind == "CONTAINS":
            self.index += 1
            return "contains"
        token = self._expect("OP")
        return str(token.value)

    def _peek(self) -> _Token:
        token = self.tokens[self.index]
        if token.kind == "IDENT" and str(token.value).lower() in {"and", "or", "contains"}:
            value = str(token.value).lower()
            return _Token(value.upper(), value)
        return token

    def _accept(self, kind: str) -> bool:
        if self._peek().kind == kind:
            self.index += 1
            return True
        return False

    def _expect(self, kind: str) -> _Token:
        token = self._peek()
        if token.kind != kind:
            raise EvidenceQueryError(f"expected {kind}, got {token.kind}")
        self.index += 1
        return token


def parse_query(expression: str):
    if not expression.strip():
        raise EvidenceQueryError("query cannot be empty")
    return _Parser(expression).parse()


def records_from_summary(summary: Mapping[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    artifact = summary.get("artifact", {})
    records.append({"scope": "artifact", **{f"artifact.{key}": value for key, value in artifact.items()}, "evidence.confidence": 1.0})
    for observation in summary.get("observations", []):
        if not isinstance(observation, Mapping):
            continue
        record = {"scope": "observation", **{f"observation.{key}": value for key, value in observation.items()}}
        record["evidence.confidence"] = _confidence(observation.get("confidence"))
        subject = str(observation.get("subject", ""))
        if subject.startswith("resource:"):
            parts = subject.removeprefix("resource:").split("/", 2)
            if len(parts) == 3:
                record.update({"resource.type": parts[0], "resource.name": parts[1], "resource.language": _number(parts[2])})
            if observation.get("property") == "size":
                record["resource.size"] = observation.get("value")
            if observation.get("property") == "sha256":
                record["resource.sha256"] = observation.get("value")
        records.append(record)
    for finding in summary.get("findings", []):
        if isinstance(finding, Mapping):
            record = {"scope": "finding", **{f"finding.{key}": value for key, value in finding.items()}}
            record["evidence.confidence"] = _confidence(finding.get("confidence"))
            records.append(record)
    for scan in summary.get("externalScans", []):
        if isinstance(scan, Mapping):
            record = {"scope": "externalScan", **{f"externalScan.{key}": value for key, value in scan.items()}}
            record["evidence.confidence"] = _confidence(scan.get("confidence", "LIMITED"))
            records.append(record)
    return records


def query_summary(summary: Mapping[str, Any], expression: str) -> list[dict[str, Any]]:
    tree = parse_query(expression)
    return [record for record in records_from_summary(summary) if _evaluate(tree, record)]


def _evaluate(node: Any, record: Mapping[str, Any]) -> bool:
    if node[0] == "and":
        return _evaluate(node[1], record) and _evaluate(node[2], record)
    if node[0] == "or":
        return _evaluate(node[1], record) or _evaluate(node[2], record)
    _, field, operator, expected = node
    if not field.startswith(("resource.", "finding.", "observation.", "evidence.", "artifact.", "externalScan.")):
        raise EvidenceQueryError(f"unsupported field namespace: {field}")
    actual = record.get(field)
    if actual is None:
        return False
    if operator == "contains":
        return str(expected).lower() in str(actual).lower()
    left, right = _coerce(actual, expected)
    if operator == "==":
        return left == right
    if operator == "!=":
        return left != right
    if operator == ">":
        return left > right
    if operator == ">=":
        return left >= right
    if operator == "<":
        return left < right
    if operator == "<=":
        return left <= right
    raise EvidenceQueryError(f"unsupported operator: {operator}")


def _coerce(actual: Any, expected: Any) -> tuple[Any, Any]:
    if isinstance(expected, (int, float)):
        if isinstance(actual, str) and actual.upper() in _CONFIDENCE:
            return _CONFIDENCE[actual.upper()], float(expected)
        try:
            return float(actual), float(expected)
        except (TypeError, ValueError) as exc:
            raise EvidenceQueryError(f"field is not numeric: {actual!r}") from exc
    if isinstance(actual, (int, float)):
        return actual, expected
    return str(actual), str(expected)


def _confidence(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    return _CONFIDENCE.get(str(value).upper(), 0.0)


def _number(value: str) -> Any:
    try:
        return int(value)
    except ValueError:
        return value


__all__ = ["EvidenceQueryError", "parse_query", "query_summary", "records_from_summary", "tokenize"]

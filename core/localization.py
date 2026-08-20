from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from typing import Iterable

_PLACEHOLDER = re.compile(r"%\d+![^!]+!|%[sd]|\{\d+\}")
_PSEUDO_MAP = str.maketrans({
    "a": "á", "e": "é", "i": "í", "o": "ó", "u": "ú",
    "A": "Á", "E": "É", "I": "Í", "O": "Ó", "U": "Ú",
})


@dataclass(frozen=True)
class LocalizedString:
    key: str
    language: str
    text: str

    def placeholders(self) -> tuple[str, ...]:
        return tuple(_PLACEHOLDER.findall(self.text))


class LocalizationCatalog:
    """Language comparison/export model independent from PE serialization."""

    def __init__(self, entries: Iterable[LocalizedString] = ()) -> None:
        self._items: dict[tuple[str, str], LocalizedString] = {
            (item.language, item.key): item for item in entries
        }

    def put(self, item: LocalizedString) -> None:
        self._items[(item.language, item.key)] = item

    def languages(self) -> tuple[str, ...]:
        return tuple(sorted({item.language for item in self._items.values()}))

    def keys(self, language: str | None = None) -> tuple[str, ...]:
        return tuple(
            sorted(
                item.key
                for item in self._items.values()
                if language is None or item.language == language
            )
        )

    def get(self, language: str, key: str) -> LocalizedString | None:
        return self._items.get((language, key))

    def compare(self, source_language: str, target_language: str) -> dict[str, list[str]]:
        source = set(self.keys(source_language))
        target = set(self.keys(target_language))
        changed = sorted(
            key
            for key in source & target
            if self.get(source_language, key).text != self.get(target_language, key).text
        )
        return {
            "missing": sorted(source - target),
            "extra": sorted(target - source),
            "changed": changed,
            "untranslated": sorted(
                key
                for key in source & target
                if self.get(source_language, key).text == self.get(target_language, key).text
            ),
        }

    def mode_report(self, source_language: str, target_language: str) -> dict[str, object]:
        return {
            "sourceLanguage": source_language,
            "targetLanguage": target_language,
            "comparison": self.compare(source_language, target_language),
            "placeholderIssues": self.validate_placeholders(source_language, target_language),
        }

    def validate_placeholders(self, source_language: str, target_language: str) -> list[dict[str, object]]:
        issues: list[dict[str, object]] = []
        for key in sorted(set(self.keys(source_language)) & set(self.keys(target_language))):
            source = self.get(source_language, key)
            target = self.get(target_language, key)
            assert source is not None and target is not None
            if source.placeholders() != target.placeholders():
                issues.append(
                    {
                        "key": key,
                        "source": source.placeholders(),
                        "target": target.placeholders(),
                    }
                )
        return issues

    def pseudo_localize(self, source_language: str, target_language: str = "qps-ploc") -> LocalizationCatalog:
        return LocalizationCatalog(
            LocalizedString(item.key, target_language, pseudo_localize_text(item.text))
            for item in self._items.values()
            if item.language == source_language
        )

    def to_json(self) -> str:
        rows = [
            {"key": item.key, "language": item.language, "text": item.text}
            for item in sorted(self._items.values(), key=lambda value: (value.language, value.key))
        ]
        return json.dumps({"format": "resource_studio.localization.v1", "entries": rows}, ensure_ascii=False, indent=2) + "\n"

    @classmethod
    def from_json(cls, text: str) -> LocalizationCatalog:
        payload = json.loads(text)
        if payload.get("format") != "resource_studio.localization.v1":
            raise ValueError("unsupported localization format")
        return cls(LocalizedString(str(row["key"]), str(row["language"]), str(row["text"])) for row in payload.get("entries", []))

    def to_csv(self) -> str:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["key", "language", "text"])
        writer.writeheader()
        for item in sorted(self._items.values(), key=lambda value: (value.language, value.key)):
            writer.writerow({"key": item.key, "language": item.language, "text": item.text})
        return output.getvalue()

    @classmethod
    def from_csv(cls, text: str) -> LocalizationCatalog:
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames is None or set(("key", "language", "text")) - set(reader.fieldnames):
            raise ValueError("localization CSV must contain key, language, text columns")
        return cls(
            LocalizedString(str(row["key"]), str(row["language"]), str(row["text"]))
            for row in reader
            if row.get("key") is not None and row.get("language") is not None and row.get("text") is not None
        )


def pseudo_localize_text(text: str) -> str:
    parts: list[str] = []
    cursor = 0
    for match in _PLACEHOLDER.finditer(text):
        parts.append(text[cursor : match.start()].translate(_PSEUDO_MAP))
        parts.append(match.group(0))
        cursor = match.end()
    parts.append(text[cursor:].translate(_PSEUDO_MAP))
    return "［" + "".join(parts) + "］"

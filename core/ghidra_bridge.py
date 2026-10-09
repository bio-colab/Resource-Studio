from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_GHIDRA_URL = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8080")


@dataclass(frozen=True)
class ControlBehaviorMapping:
    control_id: int
    control_label: str
    handler_found: bool
    matched_branch: str | None
    code_snippet: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "controlId": self.control_id,
            "controlLabel": self.control_label,
            "handlerFound": self.handler_found,
            "matchedBranch": self.matched_branch,
            "codeSnippet": self.code_snippet,
        }


_VALID_PARAM_VARS = {
    "wparam", "param_1", "param_2", "param_3", "param_4",
    "id", "wid", "controlid", "lparam", "a1", "a2", "a3", "a4", "loword"
}


def _parse_int_constant(token: str) -> int | None:
    s = re.sub(r"[uUlL]+$", "", token.strip())
    try:
        return int(s, 0)
    except ValueError:
        return None


def _line_matches_control(line: str, cid: int) -> bool:
    clean_line = re.sub(r"//.*$|/\*.*?\*/", "", line).strip()
    if not clean_line:
        return False

    # Match switch case statements: case <const>:
    case_match = re.search(r"\bcase\s*\(?\s*(0x[0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)\s*\)?\s*:", clean_line)
    if case_match:
        val = _parse_int_constant(case_match.group(1))
        if val is not None and val == cid:
            return True

    # Match structured equality comparisons around ==
    for comp_match in re.finditer(r"([^\n;{}]+?)\s*==\s*([^\n;{}]+)", clean_line):
        lhs, rhs = comp_match.group(1).strip(), comp_match.group(2).strip()

        # Check lhs constant == cid and rhs references valid message parameter variable
        lhs_nums = [_parse_int_constant(tok) for tok in re.findall(r"\b(?:0x[0-9a-fA-F]+|\d+)[uUlL]*\b", lhs)]
        rhs_ids = {tok.lower() for tok in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", rhs)}
        if any(v == cid for v in lhs_nums if v is not None) and (rhs_ids & _VALID_PARAM_VARS):
            return True

        # Check rhs constant == cid and lhs references valid message parameter variable
        rhs_nums = [_parse_int_constant(tok) for tok in re.findall(r"\b(?:0x[0-9a-fA-F]+|\d+)[uUlL]*\b", rhs)]
        lhs_ids = {tok.lower() for tok in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", lhs)}
        if any(v == cid for v in rhs_nums if v is not None) and (lhs_ids & _VALID_PARAM_VARS):
            return True

    return False


def _extract_control_snippet(lines: list[str], start_index: int, max_lines: int = 12) -> str | None:
    snippet: list[str] = []
    for j in range(start_index, min(len(lines), start_index + max_lines)):
        stripped = lines[j].strip()
        # Stop before appending if encountering next case/default branch or closing brace
        if j > start_index and re.match(r"^(?:case\b|default\b|\})", stripped):
            break
        snippet.append(lines[j].rstrip())
        # Stop after appending terminal flow statements
        if j > start_index and any(k in stripped for k in ("break;", "return;", "return ")):
            break
    return "\n".join(snippet) if snippet else None


class GhidraBridge:
    """HTTP client bridge communicating with a running GhidraMCP server plugin."""

    def __init__(self, base_url: str = DEFAULT_GHIDRA_URL, timeout: float = 2.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check_connection(self) -> dict[str, Any]:
        """Checks whether the GhidraMCP HTTP plugin is running and reachable."""
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(f"{self.base_url}/")
                return {
                    "available": True,
                    "url": self.base_url,
                    "statusCode": resp.status_code,
                    "message": "GhidraMCP server connected",
                }
        except (httpx.ConnectError, httpx.TimeoutException, OSError) as exc:
            return {
                "available": False,
                "url": self.base_url,
                "reason": f"Could not connect to GhidraMCP at {self.base_url}: {exc}",
            }

    def decompile_function(self, symbol_or_address: str) -> dict[str, Any]:
        """Requests decompilation of a function at symbol or address from Ghidra."""
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    f"{self.base_url}/decompile",
                    json={"target": symbol_or_address},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "success": True,
                        "target": symbol_or_address,
                        "code": data.get("code", resp.text),
                    }
                return {
                    "success": False,
                    "target": symbol_or_address,
                    "statusCode": resp.status_code,
                    "error": resp.text,
                }
        except (httpx.ConnectError, httpx.TimeoutException, OSError) as exc:
            return {
                "success": False,
                "target": symbol_or_address,
                "error": f"GhidraMCP connection failure: {exc}",
            }

    @staticmethod
    def parse_dialog_proc_branches(
        decompiled_code: str,
        controls: list[dict[str, Any]],
    ) -> list[ControlBehaviorMapping]:
        """Parses C pseudocode to correlate Win32 Dialog control IDs with WM_COMMAND message branches."""
        results: list[ControlBehaviorMapping] = []
        lines = decompiled_code.splitlines()

        for ctrl in controls:
            cid = ctrl.get("controlId") or ctrl.get("id") or 0
            label = str(ctrl.get("title") or ctrl.get("class") or f"Control_{cid}")

            handler_found = False
            matched_branch = None
            snippet: str | None = None

            for i, line in enumerate(lines):
                if _line_matches_control(line, int(cid)):
                    handler_found = True
                    matched_branch = line.strip()
                    snippet = _extract_control_snippet(lines, i)
                    break

            results.append(
                ControlBehaviorMapping(
                    control_id=int(cid),
                    control_label=label,
                    handler_found=handler_found,
                    matched_branch=matched_branch,
                    code_snippet=snippet,
                )
            )

        return results

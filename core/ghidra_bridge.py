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

            # Match patterns like:
            # case 1:
            # case 0x65:
            # if (LOWORD(wParam) == 101)
            # if (id == 101)
            patterns = [
                rf"case\s+(?:{cid}|0x{cid:x}|0x{cid:X})\s*:",
                rf"(?:wParam|id|wId|controlId)\s*==\s*(?:{cid}|0x{cid:x}|0x{cid:X})",
            ]

            handler_found = False
            matched_branch = None
            snippet_lines: list[str] = []

            for i, line in enumerate(lines):
                for pat in patterns:
                    if re.search(pat, line):
                        handler_found = True
                        matched_branch = line.strip()
                        # Capture up to 5 following lines of code
                        snippet_lines = [l.rstrip() for l in lines[i : min(len(lines), i + 6)]]
                        break
                if handler_found:
                    break

            snippet = "\n".join(snippet_lines) if snippet_lines else None
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

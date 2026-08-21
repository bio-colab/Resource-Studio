from __future__ import annotations

import os
import tempfile
from pathlib import Path

from core.evidence_graph import EvidenceGraph
from core.evidence_query import query_summary
from core.invariants import snapshot
from core.pe_writer import LiefPEWriter
from core.project import _entries_from_lief
from core.security_analysis import analyze_security


WINDOWS_DLLS = (
    Path(r"C:\Windows\System32\kernel32.dll"),
    Path(r"C:\Windows\System32\shell32.dll"),
)
NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


def main() -> None:
    existing = [path for path in WINDOWS_DLLS if path.is_file()]
    if not existing:
        print("real-windows-pe-contract-tests: skipped (Windows DLLs unavailable)")
        return
    for path in existing:
        state = snapshot(path)
        assert isinstance(state.exports, tuple), path
        report = analyze_security(path)
        assert "evidence" in report, path
        summary = report["evidence"]
        graph = EvidenceGraph.from_summary(summary)
        assert graph.to_dict()["schema"] == "resource_studio.evidence_graph.v1"
        assert query_summary(summary, "evidence.confidence >= 0")
        if report.get("parse", {}).get("status") != "VALID_PE":
            assert summary.get("analysisStatus") == "DEGRADED"
    if NOTEPAD.is_file():
        binary = LiefPEWriter()._parse(NOTEPAD)
        manifest = next(
            entry.data.decode("utf-8", errors="strict")
            for entry in _entries_from_lief(binary)
            if entry.resource_type == "MANIFEST"
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "notepad-manifest-roundtrip.exe"
            updated = manifest.replace("Windows Shell", "Windows Shell - Resource Studio P0")
            result = LiefPEWriter().replace_manifest(NOTEPAD, output, updated)
            assert result.verified is True
            assert result.verification["windows"]["status"] == "PASSED"
            assert result.verification["windows"]["liefComparison"]["matches"] is True
    print("real-windows-pe-contract-tests: passed")


if __name__ == "__main__":
    main()

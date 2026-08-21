from __future__ import annotations

import os
from pathlib import Path

from core.evidence_graph import EvidenceGraph
from core.evidence_query import query_summary
from core.invariants import snapshot
from core.security_analysis import analyze_security


WINDOWS_DLLS = (
    Path(r"C:\Windows\System32\kernel32.dll"),
    Path(r"C:\Windows\System32\shell32.dll"),
)


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
    print("real-windows-pe-contract-tests: passed")


if __name__ == "__main__":
    main()

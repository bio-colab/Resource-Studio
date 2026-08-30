from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from core.live_analysis import LiveAnalysisAdapter


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-live-analysis-") as directory:
        report_path = Path(directory) / "trace.json"
        target = "a" * 64
        report_path.write_text(
            json.dumps(
                {
                    "targetSha256": target,
                    "provider": "test-capture",
                    "capturedAtUtc": "2026-08-23T00:00:00Z",
                    "events": [{"api": "CreateFileW", "result": "observed"}],
                    "limitations": ["test capture"],
                }
            ),
            encoding="utf-8",
        )
        adapter = LiveAnalysisAdapter()
        session = adapter.start_session(target, provider="test-capture")
        result = adapter.import_report(session, report_path, kind="apiCallTrace")
        assert result["schema"] == "resource_studio.live_analysis.v1"
        assert result["sessionId"] == session.session_id
        assert result["targetSha256"] == target
        assert result["executedByResourceStudio"] is False
        assert result["attachedToProcess"] is False
        assert result["readOnly"] is True
        assert result["events"][0]["api"] == "CreateFileW"
        assert len(result["evidenceSha256"]) == 64
        assert hashlib.sha256(report_path.read_bytes()).hexdigest() == result["sourceSha256"]

        wrong = adapter.start_session("b" * 64)
        try:
            adapter.import_report(wrong, report_path, kind="apiCallTrace")
        except ValueError as exc:
            assert "targets" in str(exc)
        else:
            raise AssertionError("target hash mismatch was accepted")

        contract = adapter.contract()
        assert contract["schema"] == "resource_studio.live_analysis_contract.v1"
        assert contract["capabilities"]["startsProcess"] is False
        assert contract["capabilities"]["attachesToProcess"] is False
        assert contract["capabilities"]["writesTarget"] is False

    print("live-analysis-tests: passed")


if __name__ == "__main__":
    main()

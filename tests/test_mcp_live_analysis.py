from __future__ import annotations

import anyio
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "mcp" / "server.py"
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-mcp-live-") as directory:
        root = Path(directory)
        target = root / FIXTURE.name
        shutil.copy2(FIXTURE, target)
        target_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
        report = root / "api-trace.json"
        report.write_text(
            json.dumps(
                {
                    "targetSha256": target_sha256,
                    "provider": "test-capture",
                    "capturedAtUtc": "2026-08-23T00:00:00Z",
                    "events": [{"api": "CreateFileW", "result": "observed"}],
                    "limitations": ["external test capture"],
                }
            ),
            encoding="utf-8",
        )
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(SERVER)],
            cwd=str(ROOT),
            env={"RESOURCE_STUDIO_ROOT": str(root)},
        )
        async with stdio_client(params) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                registered = await session.call_tool(
                    "resource_studio.register_file", {"path": target.name}
                )
                assert not registered.is_error
                file_id = registered.structured_content["fileId"]

                contract = await session.call_tool("resource_studio.live_analysis_contract", {})
                assert not contract.is_error
                contract_payload = contract.structured_content
                assert contract_payload["schema"] == "resource_studio.live_analysis_contract.v1"
                assert contract_payload["capabilities"]["startsProcess"] is False
                assert contract_payload["capabilities"]["readsLiveMemory"] is False

                started = await session.call_tool(
                    "resource_studio.start_live_analysis_session",
                    {"file_id": file_id, "provider": "test-capture"},
                )
                assert not started.is_error
                started_payload = started.structured_content
                live_session = started_payload["session"]
                session_id = live_session["sessionId"]
                assert live_session["targetSha256"] == target_sha256
                assert live_session["attachedToProcess"] is False

                imported = await session.call_tool(
                    "resource_studio.import_live_analysis",
                    {"session_id": session_id, "path": report.name, "kind": "apiCallTrace"},
                )
                assert not imported.is_error
                imported_payload = imported.structured_content
                report_id = imported_payload["reportId"]
                evidence = imported_payload["evidence"]
                assert evidence["sessionId"] == session_id
                assert evidence["targetSha256"] == target_sha256
                assert evidence["readOnly"] is True
                assert evidence["executedByResourceStudio"] is False
                assert evidence["events"][0]["api"] == "CreateFileW"

                session_resource = await session.read_resource(
                    f"resource://live-analysis/session/{session_id}"
                )
                assert json.loads(session_resource.contents[0].text)["sessionId"] == session_id
                report_resource = await session.read_resource(
                    f"resource://live-analysis/report/{report_id}"
                )
                assert json.loads(report_resource.contents[0].text)["evidenceSha256"] == evidence["evidenceSha256"]

                state_resource = await session.read_resource("resource://session/state")
                state = json.loads(state_resource.contents[0].text)
                assert state["counts"]["liveAnalysisSessions"] == 1
                assert state["counts"]["liveAnalysisReports"] == 1
                events_resource = await session.read_resource("resource://session/events")
                event_kinds = {item["kind"] for item in json.loads(events_resource.contents[0].text)["events"]}
                assert {"live_analysis.session_started", "live_analysis.evidence_imported"}.issubset(event_kinds)

    print("mcp-live-analysis-tests: passed")


if __name__ == "__main__":
    anyio.run(main)

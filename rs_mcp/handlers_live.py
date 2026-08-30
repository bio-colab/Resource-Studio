"""Read-only live-analysis evidence session tools and resources."""
import json
import uuid
from typing import Any

from core.live_analysis import LiveAnalysisAdapter, LiveAnalysisSession

from rs_mcp.app import server
from rs_mcp.files import _file_ref, _resolve_file, _safe_path
from rs_mcp.state import LIVE_ANALYSIS_REPORTS, LIVE_ANALYSIS_SESSIONS, _persist_state, _record_event

def _live_session(session_id: str) -> LiveAnalysisSession:
    session = LIVE_ANALYSIS_SESSIONS.get(session_id)
    if session is None:
        raise ValueError(f"unknown live-analysis session: {session_id}")
    return session


@server.tool(
    name="resource_studio.live_analysis_contract",
    title="Describe live-analysis adapter",
    description="Read-only contract for externally captured live-analysis evidence; does not execute or attach to a process.",
    structured_output=True,
)
def live_analysis_contract() -> dict[str, Any]:
    return LiveAnalysisAdapter.contract()


@server.tool(
    name="resource_studio.start_live_analysis_session",
    title="Start a read-only live-analysis evidence session",
    description="Create a session bound to a registered file hash for importing external observations; no process is started or attached.",
    structured_output=True,
)
def start_live_analysis_session(file_id: str, provider: str = "external") -> dict[str, Any]:
    record = _resolve_file(file_id=file_id)
    session = LiveAnalysisAdapter().start_session(record["sha256"], provider=provider)
    LIVE_ANALYSIS_SESSIONS[session.session_id] = session
    _record_event("live_analysis.session_started", sessionId=session.session_id, fileId=file_id, targetSha256=record["sha256"], provider=session.provider)
    _persist_state()
    return {
        "schemaVersion": "resource_studio.live_analysis_session.v1",
        "session": session.to_dict(),
        "target": _file_ref(record),
        "readOnly": True,
    }


@server.tool(
    name="resource_studio.import_live_analysis",
    title="Import external live-analysis evidence",
    description="Import a bounded behavioral, memory, or API trace report whose targetSha256 matches a read-only session.",
    structured_output=True,
)
def import_live_analysis(session_id: str, path: str, kind: str) -> dict[str, Any]:
    session = _live_session(session_id)
    report_path = _safe_path(path)
    report = LiveAnalysisAdapter().import_report(session, report_path, kind=kind)
    report_id = f"live_report_{uuid.uuid4().hex[:16]}"
    LIVE_ANALYSIS_REPORTS[report_id] = report
    _record_event("live_analysis.evidence_imported", sessionId=session_id, reportId=report_id, kind=kind, targetSha256=session.target_sha256, evidenceSha256=report["evidenceSha256"])
    _persist_state()
    return {
        "schemaVersion": "resource_studio.live_analysis_result.v1",
        "reportId": report_id,
        "session": session.to_dict(),
        "evidence": report,
        "readOnly": True,
    }


@server.resource(
    "resource://live-analysis/session/{session_id}",
    name="live_analysis_session",
    title="Live-analysis evidence session",
    description="Read-only metadata for an external live-analysis evidence session.",
    mime_type="application/json",
)
def live_analysis_session_resource(session_id: str) -> str:
    return json.dumps(_live_session(session_id).to_dict(), ensure_ascii=False)


@server.resource(
    "resource://live-analysis/report/{report_id}",
    name="live_analysis_report",
    title="Imported live-analysis evidence report",
    description="Read-only normalized external observation report bound to a target hash.",
    mime_type="application/json",
)
def live_analysis_report_resource(report_id: str) -> str:
    report = LIVE_ANALYSIS_REPORTS.get(report_id)
    if report is None:
        raise ValueError(f"unknown live-analysis report: {report_id}")
    return json.dumps(report, ensure_ascii=False)

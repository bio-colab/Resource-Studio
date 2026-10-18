from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.investigation_pipeline import (
    AutomatedInvestigator,
    HypothesisVerdict,
    InvestigationHypothesis,
    InvestigationReport,
    InvestigationStage,
    InvestigationStep,
    UnknownObligation,
    replay_journal,
    run_pipeline,
)
from core.mcp_server import create_mcp_server

FIXTURE_HEAVY = ROOT / "tests" / "fixtures" / "mingw_x64_resource_heavy.exe"
FIXTURE_OVERLAY = ROOT / "tests" / "fixtures" / "mingw_x64_resource_heavy_overlay.exe"


def test_investigation_pipeline_baseline() -> None:
    """Verifies complete 5-stage automated investigation on baseline resource-heavy binary."""
    report = run_pipeline(FIXTURE_HEAVY)

    assert isinstance(report, InvestigationReport)
    assert report.pe_sha256 is not None
    assert len(report.pe_sha256) == 64
    assert report.investigation_id.startswith("RS-INV-")

    # Verify journal steps span all 5 stages
    stages = [step.stage for step in report.journal]
    assert InvestigationStage.INGESTION.value in stages
    assert InvestigationStage.TRIAGE.value in stages
    assert InvestigationStage.HYPOTHESES.value in stages
    assert InvestigationStage.EVIDENCE.value in stages
    assert InvestigationStage.VERDICT.value in stages

    # Verify every step has a valid cryptographic state hash
    for step in report.journal:
        assert isinstance(step.state_hash, str)
        assert len(step.state_hash) == 64

    # Verify report serialization
    d = report.to_dict()
    assert d["format"] == "resource_studio.investigation_report.v1"
    assert "journal" in d
    assert "hypotheses" in d
    assert "unknownsLedger" in d
    assert "humanSummary" in d
    assert len(report.human_summary) > 5


def test_investigation_pipeline_overlay_and_unknowns_ledger(tmp_path: Path) -> None:
    """Verifies that trailing overlay anomalies trigger proven hypotheses and populate the unknowns ledger."""
    report = run_pipeline(FIXTURE_OVERLAY)

    # Must contain overlay hypothesis
    overlay_hyp = next(
        (h for h in report.hypotheses if h.target_type == "SECURITY" and "OVERLAY" in h.target_name),
        None,
    )
    assert overlay_hyp is not None
    assert overlay_hyp.verdict == HypothesisVerdict.PROVEN.value
    assert overlay_hyp.confidence >= 0.95
    assert overlay_hyp.confidence_level == "HIGH"
    assert len(overlay_hyp.supporting_evidence) >= 1

    # Must have an entry in unknowns_ledger for unpacking/decryption gap
    assert len(report.unknowns_ledger) >= 1
    unk = next((u for u in report.unknowns_ledger if "OVERLAY" in u.target), None)
    assert unk is not None
    assert "Frida" in unk.recommended_action or "breakpoint" in unk.recommended_action


def test_investigation_pipeline_with_decompiled_evidence() -> None:
    """Verifies that supplying decompiled sources correctly refutes unmapped control hypotheses."""
    # Decompiled source proving control 8 has active switch handling logic
    decompiled_c = """
    INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        if (uMsg == 0x0111) {
            switch (LOWORD(wParam)) {
                case 8:
                    ExecuteAction(hDlg);
                    break;
            }
        }
        return 0;
    }
    """
    report = run_pipeline(FIXTURE_HEAVY, decompiled_sources={0: decompiled_c})

    ctrl8_hyp = next(
        (h for h in report.hypotheses if h.target_type == "CONTROL" and "Control/8" in h.target_name),
        None,
    )
    if ctrl8_hyp:
        # Since decompiled source has case 8, it must be REFUTED with high confidence
        assert ctrl8_hyp.verdict == HypothesisVerdict.REFUTED.value
        assert len(ctrl8_hyp.refuting_evidence) >= 1


def test_journal_replay_and_cryptographic_audit(tmp_path: Path) -> None:
    """Verifies that an exported journal can be audited and cryptographically replayed."""
    report = run_pipeline(FIXTURE_HEAVY)
    journal_file = tmp_path / "investigation_journal.json"
    journal_file.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

    replay_result = replay_journal(journal_file)
    assert replay_result["status"] == "AUDIT_VERIFIED"
    assert replay_result["investigationId"] == report.investigation_id
    assert replay_result["peSha256"] == report.pe_sha256
    assert replay_result["totalStepsVerified"] == len(report.journal)
    assert replay_result["reproducible"] is True


def test_mcp_investigation_tools(tmp_path: Path) -> None:
    """Verifies run_automated_investigation and replay_investigation_journal MCP tools."""
    server = create_mcp_server()
    tools = {t.name: t for t in server._tool_manager.list_tools()}

    assert "run_automated_investigation" in tools
    assert "replay_investigation_journal" in tools

    run_fn = tools["run_automated_investigation"].fn
    report_dict = run_fn(file_path=str(FIXTURE_HEAVY))
    assert report_dict["format"] == "resource_studio.investigation_report.v1"
    assert len(report_dict["journal"]) >= 5

    # Replay via MCP
    journal_file = tmp_path / "mcp_journal.json"
    journal_file.write_text(json.dumps(report_dict), encoding="utf-8")

    replay_fn = tools["replay_investigation_journal"].fn
    audit_dict = replay_fn(journal_path=str(journal_file))
    assert audit_dict["status"] == "AUDIT_VERIFIED"


def test_cli_investigate_and_replay(tmp_path: Path) -> None:
    """Verifies CLI commands 'investigate' and 'replay-investigation'."""
    import os

    journal_export = tmp_path / "cli_journal.json"
    cli_env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONPATH": str(ROOT)}

    # Run investigate command
    cmd_investigate = [
        sys.executable,
        str(ROOT / "resource_studio_cli.py"),
        "investigate",
        str(FIXTURE_OVERLAY),
        "--export-journal",
        str(journal_export),
        "--json",
    ]
    res_inv = subprocess.run(
        cmd_investigate,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        env=cli_env,
    )
    out_json = json.loads(res_inv.stdout)
    assert out_json["format"] == "resource_studio.investigation_report.v1"
    assert journal_export.exists()

    # Run replay-investigation command
    cmd_replay = [
        sys.executable,
        str(ROOT / "resource_studio_cli.py"),
        "replay-investigation",
        str(journal_export),
        "--json",
    ]
    res_rep = subprocess.run(
        cmd_replay,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        env=cli_env,
    )
    rep_json = json.loads(res_rep.stdout)
    assert rep_json["status"] == "AUDIT_VERIFIED"
    assert rep_json["reproducible"] is True

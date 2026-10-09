from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.behavioral_diff import (
    BehavioralDiffReport,
    CausalCorrelator,
    FunctionMatch,
    FunctionMatcher,
    FunctionSignature,
    ResourceComparator,
    ResourceDifference,
    compare_pe_behavior,
)
from core.mcp_server import create_mcp_server

FIXTURE_HEAVY = ROOT / "tests" / "fixtures" / "mingw_x64_resource_heavy.exe"
FIXTURE_OVERLAY = ROOT / "tests" / "fixtures" / "mingw_x64_resource_heavy_overlay.exe"


def test_function_equivalence_matching_shifted_address() -> None:
    """Verifies that functions with shifted addresses (relocated RVAs) are matched accurately."""
    f_old = FunctionSignature(
        rva=0x1000,
        size=64,
        name="sub_1000",
        section=".text",
        normalized_mnemonics=("push", "mov", "sub", "call", "cmp", "je", "xor", "ret"),
        normalized_instructions=(
            "push rbp",
            "mov rbp, rsp",
            "sub rsp, 0x30",
            "call [USER32.dll!GetDlgItem]",
            "cmp eax, 0x65",
            "je 0x1020",
            "xor eax, eax",
            "ret",
        ),
        api_calls=frozenset({"USER32.dll!GetDlgItem"}),
        immediates=frozenset({0x30, 0x65, 0x1020}),
        referenced_strings=frozenset(),
        referenced_resources=frozenset({101}),
    )

    # In new PE, code before it expanded; address shifted by +0x500 (1280 bytes)
    f_new = FunctionSignature(
        rva=0x1500,
        size=64,
        name="sub_1500",
        section=".text",
        normalized_mnemonics=("push", "mov", "sub", "call", "cmp", "je", "xor", "ret"),
        normalized_instructions=(
            "push rbp",
            "mov rbp, rsp",
            "sub rsp, 0x30",
            "call [USER32.dll!GetDlgItem]",
            "cmp eax, 0x65",
            "je 0x1520",
            "xor eax, eax",
            "ret",
        ),
        api_calls=frozenset({"USER32.dll!GetDlgItem"}),
        immediates=frozenset({0x30, 0x65, 0x1520}),
        referenced_strings=frozenset(),
        referenced_resources=frozenset({101}),
    )

    matcher = FunctionMatcher()
    sim = matcher.calculate_similarity(f_old, f_new)
    assert sim >= 0.85

    matches = matcher.match_functions([f_old], [f_new])
    assert len(matches) == 1
    match = matches[0]
    assert match.status == "RELOCATED_ONLY"
    assert match.address_delta == 0x500
    assert match.old_function.rva == 0x1000
    assert match.new_function.rva == 0x1500


def test_function_equivalence_matching_modified_constants() -> None:
    """Verifies that functions with modified constants and updated API calls match as EQUIVALENT_MODIFIED."""
    f_old = FunctionSignature(
        rva=0x2000,
        size=80,
        name="sub_2000",
        section=".text",
        normalized_mnemonics=("push", "mov", "sub", "cmp", "je", "call", "add", "ret"),
        normalized_instructions=(
            "push rbp",
            "mov rbp, rsp",
            "sub rsp, 0x20",
            "cmp r8d, 105",  # Handled old button 105
            "je 0x2040",
            "call [KERNEL32.dll!DeleteFileW]",
            "add rsp, 0x20",
            "ret",
        ),
        api_calls=frozenset({"KERNEL32.dll!DeleteFileW"}),
        immediates=frozenset({0x20, 105}),
        referenced_strings=frozenset(),
        referenced_resources=frozenset({105}),
    )

    f_new = FunctionSignature(
        rva=0x2000,
        size=88,
        name="sub_2000",
        section=".text",
        normalized_mnemonics=("push", "mov", "sub", "cmp", "je", "call", "add", "ret"),
        normalized_instructions=(
            "push rbp",
            "mov rbp, rsp",
            "sub rsp, 0x20",
            "cmp r8d, 108",  # Now handles new button 108
            "je 0x2040",
            "call [WININET.dll!HttpSendRequestW]",
            "add rsp, 0x20",
            "ret",
        ),
        api_calls=frozenset({"WININET.dll!HttpSendRequestW"}),
        immediates=frozenset({0x20, 108}),
        referenced_strings=frozenset(),
        referenced_resources=frozenset({108}),
    )

    matcher = FunctionMatcher()
    sim = matcher.calculate_similarity(f_old, f_new)
    assert sim >= 0.60

    matches = matcher.match_functions([f_old], [f_new])
    assert len(matches) == 1
    match = matches[0]
    assert match.status == "EQUIVALENT_MODIFIED"
    assert 105 in match.constants_changed
    assert 108 in match.constants_changed
    assert "WININET.dll!HttpSendRequestW" in match.api_calls_added
    assert "KERNEL32.dll!DeleteFileW" in match.api_calls_removed


def test_causal_correlation_explains_resource_changes() -> None:
    """Verifies that UI differences are causally connected to code changes explaining what and why."""
    f_old = FunctionSignature(
        rva=0x3000,
        size=100,
        name="DialogProc_Old",
        section=".text",
        normalized_mnemonics=("push", "mov", "sub", "cmp", "call", "ret"),
        normalized_instructions=("cmp r8d, 105", "call [KERNEL32.dll!DeleteFileW]"),
        api_calls=frozenset({"KERNEL32.dll!DeleteFileW"}),
        immediates=frozenset({105}),
        referenced_strings=frozenset(),
        referenced_resources=frozenset({105}),
    )

    f_new = FunctionSignature(
        rva=0x3400,
        size=120,
        name="DialogProc_New",
        section=".text",
        normalized_mnemonics=("push", "mov", "sub", "cmp", "call", "ret"),
        normalized_instructions=("cmp r8d, 108", "call [WININET.dll!HttpSendRequestW]"),
        api_calls=frozenset({"WININET.dll!HttpSendRequestW"}),
        immediates=frozenset({108}),
        referenced_strings=frozenset(),
        referenced_resources=frozenset({108}),
    )

    f_match = FunctionMatch(
        old_function=f_old,
        new_function=f_new,
        similarity=0.80,
        status="EQUIVALENT_MODIFIED",
        address_delta=0x400,
        constants_changed=(105, 108),
        api_calls_added=("WININET.dll!HttpSendRequestW",),
        api_calls_removed=("KERNEL32.dll!DeleteFileW",),
    )

    diffs = [
        ResourceDifference(
            resource_type="DIALOG_CONTROL",
            resource_name="201",
            item_id=105,
            item_label="BUTTON 'Delete Item'",
            change_type="REMOVED",
        ),
        ResourceDifference(
            resource_type="DIALOG_CONTROL",
            resource_name="201",
            item_id=108,
            item_label="BUTTON 'Sync Cloud'",
            change_type="ADDED",
        ),
    ]

    correlations = CausalCorrelator.correlate(diffs, [f_match])
    assert len(correlations) == 2

    # Check removal causal explanation
    c_removed = next(c for c in correlations if c.change_type == "CONTROL_OR_ITEM_REMOVED")
    assert "105" in c_removed.code_explanation
    assert "0x3000" in c_removed.code_explanation
    assert "0x3400" in c_removed.code_explanation
    assert "KERNEL32.dll!DeleteFileW" in c_removed.code_explanation

    # Check addition causal explanation
    c_added = next(c for c in correlations if c.change_type == "CONTROL_OR_ITEM_ADDED")
    assert "108" in c_added.code_explanation
    assert "0x3400" in c_added.code_explanation
    assert "WININET.dll!HttpSendRequestW" in c_added.code_explanation


def test_compare_pe_behavior_on_fixtures() -> None:
    """Verifies compare_pe_behavior pipeline on real fixtures."""
    report = compare_pe_behavior(FIXTURE_HEAVY, FIXTURE_OVERLAY)
    assert isinstance(report, BehavioralDiffReport)
    assert report.summary["matchedCount"] == 46
    assert len(report.function_matches) == 46
    assert any("ما الذي تغيّر" in line for line in report.human_summary)
    assert any("ما التغيير البرمجي" in line for line in report.human_summary)


@pytest.mark.asyncio
async def test_mcp_diff_pe_behavior_tool() -> None:
    """Verifies FastMCP tool invocation for diff_pe_behavior."""
    server = create_mcp_server()
    tools = await server.list_tools()
    assert any(t.name == "diff_pe_behavior" for t in tools)

    _, result = await server.call_tool(
        "diff_pe_behavior",
        {
            "old_path": str(FIXTURE_HEAVY),
            "new_path": str(FIXTURE_OVERLAY),
        },
    )
    assert "summary" in result
    assert result["summary"]["matchedCount"] == 46
    assert "humanSummary" in result
    assert isinstance(result["humanSummary"], list)


def test_cli_behavioral_diff_command() -> None:
    """Verifies that resource_studio_cli.py behavioral-diff executes and returns JSON."""
    import os

    res = subprocess.run(
        [
            sys.executable,
            str(ROOT / "resource_studio_cli.py"),
            "behavioral-diff",
            str(FIXTURE_HEAVY),
            str(FIXTURE_OVERLAY),
            "--json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        check=True,
    )
    data = json.loads(res.stdout)
    assert data["summary"]["matchedCount"] == 46
    assert data["oldPath"]
    assert data["newPath"]

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.ghidra_bridge import GhidraBridge
from core.mcp_server import create_mcp_server

FIXTURE_HEAVY = ROOT / "tests" / "fixtures" / "mingw_x64_resource_heavy.exe"

SAMPLE_DECOMPILED_DIALOGPROC = """
INT_PTR CALLBACK MyDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == 0x0110) { // WM_INITDIALOG
        InitializeControls(hDlg);
        return 1;
    }
    if (uMsg == 0x0111) { // WM_COMMAND
        switch (LOWORD(wParam)) {
            case 1: // IDOK
                CommitChanges();
                EndDialog(hDlg, 1);
                return 1;
            case 2: // IDCANCEL
                EndDialog(hDlg, 0);
                return 1;
            case 8: // Custom control ID 8 (as in fixture dialog 201)
                TriggerSpecialAction();
                return 1;
        }
    }
    return 0;
}
"""


def test_bridge_connection_offline() -> None:
    bridge = GhidraBridge(base_url="http://127.0.0.1:59999", timeout=0.5)
    status = bridge.check_connection()
    assert status["available"] is False
    assert "Could not connect" in status["reason"]

    decompile = bridge.decompile_function("DialogProc")
    assert decompile["success"] is False
    assert "failure" in decompile["error"].lower()


def test_dialog_proc_branch_parsing() -> None:
    controls = [
        {"controlId": 1, "title": "OK"},
        {"controlId": 2, "title": "Cancel"},
        {"controlId": 8, "title": "SpecialBtn"},
        {"controlId": 999, "title": "Missing"},
    ]
    mappings = GhidraBridge.parse_dialog_proc_branches(SAMPLE_DECOMPILED_DIALOGPROC, controls)
    assert len(mappings) == 4

    m_map = {m.control_id: m for m in mappings}
    assert m_map[1].handler_found is True
    assert "case 1:" in m_map[1].matched_branch
    assert "CommitChanges()" in m_map[1].code_snippet

    assert m_map[2].handler_found is True
    assert "case 2:" in m_map[2].matched_branch

    assert m_map[8].handler_found is True
    assert "case 8:" in m_map[8].matched_branch
    assert "TriggerSpecialAction()" in m_map[8].code_snippet

    assert m_map[999].handler_found is False
    assert m_map[999].matched_branch is None


def test_cli_ghidra_status() -> None:
    res = subprocess.run(
        [sys.executable, str(ROOT / "resource_studio_cli.py"), "ghidra", "status", "--url", "http://127.0.0.1:59999", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["available"] is False


def test_mcp_correlate_dialog_behavior() -> None:
    async def _run() -> None:
        server = create_mcp_server()
        _, res = await server.call_tool(
            "correlate_dialog_behavior",
            {
                "file_path": str(FIXTURE_HEAVY),
                "dialog_name": "201",
                "decompiled_code": SAMPLE_DECOMPILED_DIALOGPROC,
            },
        )
        assert res["dialogName"] == "201"
        assert res["hasCodeMapping"] is True
        assert len(res["mappings"]) == 2  # Dialog 201 has 2 controls (including ID 8)
        c8 = next(m for m in res["mappings"] if m["controlId"] == 8)
        assert c8["handlerFound"] is True
        assert "TriggerSpecialAction()" in c8["codeSnippet"]

    asyncio.run(_run())


def main() -> None:
    test_bridge_connection_offline()
    test_dialog_proc_branch_parsing()
    test_cli_ghidra_status()
    test_mcp_correlate_dialog_behavior()
    print("test_ghidra_bridge: all 4 test suites passed successfully!")


if __name__ == "__main__":
    main()

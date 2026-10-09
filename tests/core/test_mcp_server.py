from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.mcp_server import create_mcp_server
from core.pe_writer import LiefPEWriter

FIXTURE_SAMPLE = ROOT / "tests" / "fixtures" / "sample.dll"
FIXTURE_HEAVY = ROOT / "tests" / "fixtures" / "mingw_x64_resource_heavy.exe"


def test_server_registration() -> None:
    async def _run() -> None:
        server = create_mcp_server()
        tools = await server.list_tools()
        tool_names = {t.name for t in tools}
        expected_tools = {
            "list_pe_resources",
            "inspect_pe",
            "validate_pe",
            "extract_resource",
            "diff_pe_resources",
            "analyze_dialog",
            "export_recipe",
            "apply_recipe",
            "generate_developer_code",
            "inspect_security",
            "scan_resource_xrefs",
            "correlate_dialog_behavior",
        }
        assert expected_tools.issubset(tool_names), f"Missing tools: {expected_tools - tool_names}"

        prompts = await server.list_prompts()
        prompt_names = {p.name for p in prompts}
        assert "triage_pe_resources" in prompt_names
        assert "plan_resource_patch" in prompt_names

    asyncio.run(_run())


def test_tool_list_and_inspect_pe() -> None:
    async def _run() -> None:
        server = create_mcp_server()
        _, list_res = await server.call_tool("list_pe_resources", {"file_path": str(FIXTURE_SAMPLE)})
        assert isinstance(list_res, dict) and "result" in list_res
        entries = list_res["result"]
        assert len(entries) >= 1
        assert any(e["type"] == "MANIFEST" for e in entries)

        _, insp_res = await server.call_tool("inspect_pe", {"file_path": str(FIXTURE_SAMPLE)})
        assert insp_res["machine"] == "MACHINE_TYPES.AMD64"
        assert len(insp_res["sections"]) == 7

    asyncio.run(_run())


def test_tool_validate_and_security() -> None:
    async def _run() -> None:
        server = create_mcp_server()
        _, val_res = await server.call_tool("validate_pe", {"file_path": str(FIXTURE_SAMPLE)})
        assert val_res["valid"] is True
        assert val_res["status"] == "VALID_PE"

        _, sec_res = await server.call_tool("inspect_security", {"file_path": str(FIXTURE_SAMPLE)})
        assert sec_res["signed"] is False
        assert sec_res["pdbPath"] is not None
        assert "test.pdb" in sec_res["pdbPath"]

    asyncio.run(_run())


def test_tool_extract_and_generate_code() -> None:
    async def _run() -> None:
        server = create_mcp_server()
        with tempfile.TemporaryDirectory() as td:
            out_file = Path(td) / "extracted_manifest.bin"
            _, ext_res = await server.call_tool(
                "extract_resource",
                {
                    "file_path": str(FIXTURE_SAMPLE),
                    "resource_type": "MANIFEST",
                    "resource_name": "1",
                    "output_path": str(out_file),
                },
            )
            assert ext_res["size"] == 381
            assert out_file.is_file()
            assert len(out_file.read_bytes()) == 381
            assert ext_res["base64"] is not None

        # Test code generator formats
        for kind in ("c_array", "csharp_span", "base64", "sha256", "resource_h"):
            _, code_res = await server.call_tool(
                "generate_developer_code",
                {
                    "file_path": str(FIXTURE_SAMPLE),
                    "resource_type": "MANIFEST",
                    "resource_name": "1",
                    "code_kind": kind,
                },
            )
            assert code_res["kind"] == kind
            snippet = code_res["snippet"]
            if kind == "c_array":
                assert "const unsigned char res_MANIFEST_1[]" in snippet
            elif kind == "csharp_span":
                assert "ReadOnlySpan<byte> res_MANIFEST_1 = [" in snippet
            elif kind == "base64":
                assert len(base64.b64decode(snippet)) == 381
            elif kind == "sha256":
                assert len(snippet) == 64
            elif kind == "resource_h":
                assert "#define IDR_MANIFEST_1" in snippet

    asyncio.run(_run())


def test_tool_diff_and_dialog_analysis() -> None:
    async def _run() -> None:
        server = create_mcp_server()
        # Diff identical file
        _, diff_res = await server.call_tool(
            "diff_pe_resources",
            {"left_path": str(FIXTURE_SAMPLE), "right_path": str(FIXTURE_SAMPLE)},
        )
        assert diff_res["filesIdentical"] is True
        assert diff_res["changeCount"] == 0

        # Dialog clipping analysis on fixture
        _, dlg_res = await server.call_tool(
            "analyze_dialog",
            {"file_path": str(FIXTURE_HEAVY), "dialog_name": "201"},
        )
        assert dlg_res["dialogName"] == "201"
        assert dlg_res["controlCount"] == 2
        assert dlg_res["clippingRiskCount"] >= 1

    asyncio.run(_run())


def test_tool_recipe_export_and_apply() -> None:
    async def _run() -> None:
        server = create_mcp_server()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            edited_dll = tdp / "sample_edited.dll"
            LiefPEWriter().replace_resource(
                FIXTURE_SAMPLE,
                edited_dll,
                "MANIFEST",
                1,
                1033,
                b"<!-- MCP Recipe Test Payload -->",
            )
            recipe_dir = tdp / "test_recipe"
            _, exp_res = await server.call_tool(
                "export_recipe",
                {
                    "original_path": str(FIXTURE_SAMPLE),
                    "edited_path": str(edited_dll),
                    "output_dir": str(recipe_dir),
                },
            )
            assert exp_res["verified"] is True
            assert exp_res["operationCount"] == 1

            patched_dll = tdp / "sample_patched.dll"
            _, app_res = await server.call_tool(
                "apply_recipe",
                {
                    "target_path": str(FIXTURE_SAMPLE),
                    "recipe_path": str(recipe_dir / "recipe.json"),
                    "output_path": str(patched_dll),
                },
            )
            assert app_res["status"] == "ok"
            assert patched_dll.is_file()

    asyncio.run(_run())


def test_cli_mcp_invocation() -> None:
    res = subprocess.run(
        [sys.executable, str(ROOT / "resource_studio_cli.py"), "mcp", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    assert "MCP transport protocol" in res.stdout


def main() -> None:
    test_server_registration()
    test_tool_list_and_inspect_pe()
    test_tool_validate_and_security()
    test_tool_extract_and_generate_code()
    test_tool_diff_and_dialog_analysis()
    test_tool_recipe_export_and_apply()
    test_cli_mcp_invocation()
    print("test_mcp_server: all 7 test suites passed successfully!")


if __name__ == "__main__":
    main()

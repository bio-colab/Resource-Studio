from __future__ import annotations

from pathlib import Path
import pytest
import capstone

from core.value_flow_tracker import ValueFlowTracker, ValueFlowBinding
from core.managed_pe import ManagedPEParser
from core.toolchain_auditor import ToolchainAuditor
from core.runtime_tracer import RuntimeTracer
from core.mcp_server import create_mcp_server


def test_value_flow_tracker_lea_zero_register():
    """Verify that ValueFlowTracker correctly tracks XOR zeroing and LEA displacement calculation."""
    # 64-bit code:
    # 0x1000: xor eax, eax         (31 c0)
    # 0x1002: lea edx, [rax + 0x71] (8d 50 71)
    code = bytes([0x31, 0xC0, 0x8D, 0x50, 0x71])
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True

    tracker = ValueFlowTracker(is_64bit=True)
    for insn in cs.disasm(code, 0x1000):
        tracker.process_instruction(insn)

    binding = tracker.resolve_api_call("LoadStringW", 0x1005)
    assert binding is not None
    assert binding.target_id == 113
    assert binding.register_used == "rdx"
    assert binding.confidence == "PROVEN_REGISTER_FLOW"
    assert "xor eax, eax" in binding.evidence_instructions[0]
    assert "lea edx, [rax + 0x71]" in binding.evidence_instructions[1]


def test_value_flow_tracker_register_arithmetic():
    """Verify that ValueFlowTracker propagates known register constants through arithmetic LEA."""
    # 0x1000: mov r9d, 0x100       (41 b9 00 01 00 00)
    # 0x1006: lea edx, [r9 + 0x2c]  (67 41 8d 51 2c)
    code = bytes([0x41, 0xB9, 0x00, 0x01, 0x00, 0x00, 0x67, 0x41, 0x8D, 0x51, 0x2C])
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True

    tracker = ValueFlowTracker(is_64bit=True)
    for insn in cs.disasm(code, 0x1000):
        tracker.process_instruction(insn)

    binding = tracker.resolve_api_call("LoadStringW", 0x100B)
    assert binding is not None
    assert binding.target_id == 300  # 0x100 + 0x2c = 256 + 44 = 300
    assert binding.confidence == "PROVEN_REGISTER_FLOW"


def test_value_flow_tracker_x86_stack_abi():
    """Verify that ValueFlowTracker tracks stack pushes for 32-bit stdcall resource APIs."""
    # 32-bit code:
    # 0x1000: push 0x50     (6a 50) - cchMax (arg3)
    # 0x1002: push 0x123456 (68 56 34 12 00) - lpBuffer (arg2)
    # 0x1007: push 0x65     (6a 65) - uID = 101 (arg1)
    # 0x1009: push 0x400000 (68 00 00 40 00) - hInstance (arg0)
    code = bytes([0x6A, 0x50, 0x68, 0x56, 0x34, 0x12, 0x00, 0x6A, 0x65, 0x68, 0x00, 0x00, 0x40, 0x00])
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True

    tracker = ValueFlowTracker(is_64bit=False)
    for insn in cs.disasm(code, 0x1000):
        tracker.process_instruction(insn)

    binding = tracker.resolve_api_call("LoadStringW", 0x100E)
    assert binding is not None
    assert binding.target_id == 101
    assert binding.register_used == "stack"


def test_managed_pe_parser_real_or_synthetic():
    """Verify ManagedPEParser against real MSBuild.exe if present on Windows host."""
    msbuild = Path("C:/Windows/Microsoft.NET/Framework64/v4.0.30319/MSBuild.exe")
    if not msbuild.is_file():
        pytest.skip("MSBuild.exe not available on host")

    parser = ManagedPEParser(msbuild)
    rep = parser.parse()
    assert rep.is_managed is True
    assert rep.runtime_version == "2.5"
    assert rep.metadata_version == "v4.0.30319"
    assert rep.cli_flags == 9
    assert "il-only" in rep.cli_flag_names
    assert "strong-name-signed" in rep.cli_flag_names
    assert "#US" in rep.stream_names
    assert "#Strings" in rep.stream_names
    assert len(rep.manifest_resources) == 2
    res_names = {r.name for r in rep.manifest_resources}
    assert "MSBuild.Strings.resources" in res_names
    assert "MSBuild.Strings.shared.resources" in res_names
    assert len(rep.user_strings) > 500


def test_toolchain_auditor_real_or_synthetic():
    """Verify ToolchainAuditor against real Go and Rust binaries on host."""
    gh = Path("C:/Program Files/GitHub CLI/gh.exe")
    if gh.is_file():
        auditor = ToolchainAuditor(gh)
        rep = auditor.audit()
        assert rep.toolchain_type == "GO"
        assert rep.go_info is not None
        assert rep.go_info.version is not None and "go" in rep.go_info.version
        assert rep.go_info.main_module == "github.com/cli/cli/v2"
        assert len(rep.go_info.dependencies) > 100

    rg = Path("C:/Users/Eylias/AppData/Local/OpenAI/Codex/bin/9a7ba4b9ea0c44a3/rg.exe")
    if rg.is_file():
        auditor = ToolchainAuditor(rg)
        rep = auditor.audit()
        assert rep.toolchain_type == "RUST"
        assert rep.rust_info is not None
        assert rep.rust_info.rustc_commit == "e408947bfd200af42db322daf0fadfe7e26d3bd1"


def test_runtime_tracer_frida_script_and_event():
    """Verify Frida hook script generation and event parsing."""
    script = RuntimeTracer.get_frida_script()
    assert "LoadStringW" in script
    assert "FindResourceW" in script
    assert "CreateDialogParamW" in script
    assert "LoadImageW" in script

    ev = RuntimeTracer.parse_event({
        "payload": {
            "event": "CREATE_DIALOG",
            "api": "CreateDialogParamW",
            "resourceType": "DIALOG",
            "templateName": 101,
            "templateKind": "ID",
            "dialogProc": "0x14000aef0",
            "hInstance": "0x140000000",
        }
    })
    assert ev is not None
    assert ev.event_type == "CREATE_DIALOG"
    assert ev.resource_id_or_name == 101


def test_mcp_server_new_empirical_tools(tmp_path):
    """Verify newly registered MCP tools in Resource Studio FastMCP server."""
    server = create_mcp_server()
    # Check that inspect_managed_artifact, inspect_toolchain, trace_native_values are registered
    tool_names = [t.name for t in server._tool_manager.list_tools()]
    assert "inspect_managed_artifact" in tool_names
    assert "inspect_toolchain" in tool_names
    assert "trace_native_values" in tool_names

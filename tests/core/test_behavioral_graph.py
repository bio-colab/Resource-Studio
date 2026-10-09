from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.behavioral_graph import (
    BehavioralGraphEngine,
    BehavioralTrace,
    EvidenceRecord,
    GraphEdge,
    GraphNode,
    ResourceBehaviorGraph,
    build_resource_behavior_graph,
)
from core.mcp_server import create_mcp_server

FIXTURE_HEAVY = ROOT / "tests" / "fixtures" / "mingw_x64_resource_heavy.exe"


def test_behavioral_graph_structure_and_mermaid() -> None:
    """Verifies that the graph engine extracts resources, dialog controls, and generates valid Mermaid syntax."""
    graph = build_resource_behavior_graph(FIXTURE_HEAVY)
    assert isinstance(graph, ResourceBehaviorGraph)
    assert len(graph.nodes) >= 7
    assert len(graph.edges) >= 1

    # Check DIALOG 201 node
    d_node = next((n for n in graph.nodes if n.node_type == "RESOURCE" and "DIALOG 201" in n.label), None)
    assert d_node is not None
    assert d_node.attributes["type"] == "DIALOG"

    # Check Control 8 node
    c_node = next((n for n in graph.nodes if n.node_type == "CONTROL" and n.attributes.get("controlId") == 8), None)
    assert c_node is not None

    # Check CONTAINS_CONTROL edge
    edge = next((e for e in graph.edges if e.edge_type == "CONTAINS_CONTROL" and e.target == c_node.id), None)
    assert edge is not None
    assert edge.confidence == 1.0
    assert edge.confidence_level == "HIGH"
    assert edge.evidence.source == "PE_RESOURCE_DIRECTORY"

    # Check Mermaid diagram
    assert graph.mermaid_diagram.startswith("flowchart LR")
    assert "res_DIALOG_201" in graph.mermaid_diagram
    assert "ctrl_201_8" in graph.mermaid_diagram


def test_behavioral_graph_with_decompiled_dialog_proc() -> None:
    """Verifies end-to-end tracing: Dialog -> Control -> WM_COMMAND branch -> Handler -> Secondary Resources."""
    # Simulate a decompiled DialogProc C pseudocode (from GhidraMCP)
    decompiled_dialog_proc = """
    INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        if (uMsg == 0x0111) { // WM_COMMAND
            int id = LOWORD(wParam);
            switch (id) {
                case 8: {
                    ProcessItem8(hDlg);
                    LoadStringW(g_hInst, 1, buffer, 256);
                    DeleteFileW(L"temp.dat");
                    break;
                }
                case 999: {
                    EndDialog(hDlg, 0);
                    break;
                }
            }
        }
        return 0;
    }
    """

    engine = BehavioralGraphEngine(
        FIXTURE_HEAVY,
        decompiled_sources={"sub_1000": decompiled_dialog_proc, 0x1000: decompiled_dialog_proc, "0x1000": decompiled_dialog_proc},
    )

    # Inject mock call site linking DIALOG 201 to DialogProc at 0x1000
    mock_call_site = {
        "api": "USER32.dll!DialogBoxParamW",
        "target_type": "DIALOG",
        "target_name": "201",
        "caller_rva_hex": "0x2000",
        "call_address_hex": "0x140002050",
        "section": ".text",
        "instruction": "call [USER32.dll!DialogBoxParamW]",
        "dialog_proc_rva_hex": "0x1000",
        "confidence": 0.95,
        "confidence_level": "HIGH",
        "evidence_source": "CAPSTONE_DISASSEMBLER",
        "verification_rationale": "Explicit DialogBoxParamW call passing Dialog 201 and lpDialogFunc=0x1000",
    }
    engine._scan_resource_call_sites = lambda: [mock_call_site]

    graph = engine.build_graph()

    # Check caller function node
    caller = next((n for n in graph.nodes if n.id == "func:0x2000"), None)
    assert caller is not None

    # Check DialogProc function node
    proc = next((n for n in graph.nodes if n.id == "func:0x1000"), None)
    assert proc is not None

    # Check branch node for Control 8
    branch = next((n for n in graph.nodes if n.node_type == "BRANCH" and n.attributes.get("controlId") == 8), None)
    assert branch is not None

    # Check DISPATCHES_TO edge
    disp_edge = next((e for e in graph.edges if e.edge_type == "DISPATCHES_TO"), None)
    assert disp_edge is not None
    assert disp_edge.confidence >= 0.90
    assert disp_edge.confidence_level == "HIGH"
    assert disp_edge.evidence.source == "GHIDRA_DECOMPILER"
    assert "case 8" in str(disp_edge.evidence.code_snippet)

    # Check called handler function
    handler = next((n for n in graph.nodes if "ProcessItem8" in n.label), None)
    assert handler is not None

    # Check secondary resource access (LoadStringW -> STRING 1)
    sec_res = next((n for n in graph.nodes if "STRING 1" in n.label), None)
    assert sec_res is not None

    # Check traces
    assert len(graph.traces) >= 1
    t = graph.traces[0]
    assert t.resource_id == "DIALOG_201"
    assert t.control_id == "8"
    assert t.confidence >= 0.90
    assert t.confidence_level == "HIGH"
    assert any("case 8" in ev for ev in t.evidence_summary)


@pytest.mark.asyncio
async def test_mcp_generate_resource_behavior_graph_tool() -> None:
    """Verifies that the FastMCP server exposes generate_resource_behavior_graph and returns factual graph data."""
    server = create_mcp_server()
    tools = await server.list_tools()
    assert any(t.name == "generate_resource_behavior_graph" for t in tools)

    _, result = await server.call_tool(
        "generate_resource_behavior_graph",
        {
            "file_path": str(FIXTURE_HEAVY),
        },
    )
    assert "nodeCount" in result
    assert "edgeCount" in result
    assert "nodes" in result
    assert "edges" in result
    assert "mermaid" in result
    assert result["nodeCount"] >= 7


def test_cli_behavioral_graph_command() -> None:
    """Verifies resource_studio_cli.py behavioral-graph command execution."""
    import os

    res = subprocess.run(
        [
            sys.executable,
            str(ROOT / "resource_studio_cli.py"),
            "behavioral-graph",
            str(FIXTURE_HEAVY),
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
    assert data["nodeCount"] >= 7
    assert data["mermaid"]

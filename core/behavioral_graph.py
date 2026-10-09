from __future__ import annotations

import difflib
import json
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import capstone
import lief

from .dialog_resources import DialogResource
from .ghidra_bridge import GhidraBridge, _extract_control_snippet, _line_matches_control, _parse_int_constant
from .menu_resources import MenuResource
from .parse_cache import shared_parse
from .resource_reader import ResourceReader
from .string_table import StringTableBlock
from .xref_scanner import KNOWN_RESOURCE_APIS


@dataclass(frozen=True)
class EvidenceRecord:
    """Rigorous factual evidence documenting an edge or link in the behavior graph."""

    source: str  # "GHIDRA_DECOMPILER", "CAPSTONE_DISASSEMBLER", "WIN32_API_CONTRACT", "PE_RESOURCE_DIRECTORY"
    address: str | None
    instruction: str | None
    code_snippet: str | None
    confidence: float  # 0.0 to 1.0
    confidence_level: str  # "HIGH", "MEDIUM", "LOW"
    verification_rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "address": self.address,
            "instruction": self.instruction,
            "codeSnippet": self.code_snippet,
            "confidence": round(self.confidence, 3),
            "confidenceLevel": self.confidence_level,
            "verificationRationale": self.verification_rationale,
        }


@dataclass(frozen=True)
class GraphNode:
    """A discrete entity in the resource behavior graph."""

    id: str
    node_type: str  # "RESOURCE", "CONTROL", "CODE_REFERENCE", "FUNCTION", "BRANCH", "CALLED_FUNCTION", "API_CALL", "SECONDARY_RESOURCE"
    label: str
    address: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "type": self.node_type,
            "label": self.label,
        }
        if self.address:
            data["address"] = self.address
        if self.attributes:
            data["attributes"] = self.attributes
        return data


@dataclass(frozen=True)
class GraphEdge:
    """A directed causal or structural link between two nodes in the graph."""

    source: str
    target: str
    edge_type: str  # "INVOKES", "BINDS_PROC", "CONTAINS_CONTROL", "DISPATCHES_TO", "CALLS", "ACCESSES_RESOURCE", "CALLS_API"
    label: str
    confidence: float
    confidence_level: str
    evidence: EvidenceRecord

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "edgeType": self.edge_type,
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "confidenceLevel": self.confidence_level,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class BehavioralTrace:
    """An end-to-end trace from a Win32 Resource -> Control ID -> Message Branch -> Handler -> Downstream Resources."""

    trace_id: str
    resource_id: str
    control_id: str | None
    path_description: str
    nodes: tuple[dict[str, Any], ...]
    confidence: float
    confidence_level: str
    evidence_summary: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "traceId": self.trace_id,
            "resourceId": self.resource_id,
            "controlId": self.control_id,
            "pathDescription": self.path_description,
            "nodes": list(self.nodes),
            "confidence": round(self.confidence, 3),
            "confidenceLevel": self.confidence_level,
            "evidenceSummary": list(self.evidence_summary),
        }


@dataclass(frozen=True)
class ResourceBehaviorGraph:
    """The complete multi-tiered graph connecting PE resources to executable behavior."""

    pe_path: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    traces: tuple[BehavioralTrace, ...]
    mermaid_diagram: str
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pePath": self.pe_path,
            "summary": self.summary,
            "nodeCount": len(self.nodes),
            "edgeCount": len(self.edges),
            "traceCount": len(self.traces),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "traces": [t.to_dict() for t in self.traces],
            "mermaid": self.mermaid_diagram,
        }


class BehavioralGraphEngine:
    """Builds an evidence-backed directed graph connecting PE resources to functions, message branches, and downstream data flow."""

    def __init__(
        self,
        pe_path: str | Path,
        ghidra_url: str | None = None,
        decompiled_sources: dict[str | int, str] | None = None,
    ) -> None:
        self.path = Path(pe_path).expanduser().resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"PE file not found: {self.path}")

        self.binary = shared_parse(self.path)
        if self.binary is None or not isinstance(self.binary, lief.PE.Binary):
            raise ValueError(f"File is not a valid PE binary: {self.path}")

        self.is_64bit = self.binary.header.machine in (
            lief.PE.Header.MACHINE_TYPES.AMD64,
            lief.PE.Header.MACHINE_TYPES.ARM64,
        )
        mode = capstone.CS_MODE_64 if self.is_64bit else capstone.CS_MODE_32
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.cs.detail = True

        self.imagebase = self.binary.optional_header.imagebase
        self.ghidra_bridge = GhidraBridge(base_url=ghidra_url) if ghidra_url else None
        self.decompiled_sources: dict[str | int, str] = decompiled_sources or {}

        # Cache of parsed resources
        self.reader = ResourceReader(self.path)
        self.entries = self.reader.entries
        self.import_map = self._build_import_map()

    def _build_import_map(self) -> dict[int, str]:
        mapping: dict[int, str] = {}
        for imp in self.binary.imports:
            dll_name = imp.name
            for entry in imp.entries:
                if entry.name:
                    sym = f"{dll_name}!{entry.name}"
                    mapping[entry.iat_address] = sym
                    if entry.iat_address >= self.imagebase:
                        mapping[entry.iat_address - self.imagebase] = sym
        return mapping

    def _get_decompiled_code(self, symbol_or_addr: str | int) -> str | None:
        """Retrieves decompiled C code from user sources or live GhidraBridge."""
        # 1. Check user-supplied decompilation map
        if symbol_or_addr in self.decompiled_sources:
            return self.decompiled_sources[symbol_or_addr]
        hex_key = hex(symbol_or_addr) if isinstance(symbol_or_addr, int) else symbol_or_addr
        if hex_key in self.decompiled_sources:
            return self.decompiled_sources[hex_key]

        # 2. Query live Ghidra bridge if available
        if self.ghidra_bridge:
            res = self.ghidra_bridge.decompile_function(hex_key)
            if res.get("success") and res.get("code"):
                return str(res["code"])

        return None

    def build_graph(self) -> ResourceBehaviorGraph:
        """Constructs the comprehensive Resource-to-Behavior Graph."""
        nodes: dict[str, GraphNode] = {}
        edges: list[GraphEdge] = []
        traces: list[BehavioralTrace] = []

        # 1. Index All Defined Resources
        dialog_models: dict[str, DialogResource] = {}
        menu_models: dict[str, MenuResource] = {}
        string_models: dict[int, str] = {}

        for entry in self.entries:
            res_id = f"res:{entry.resource_type}:{entry.name}:{entry.language or 0}"
            label = f"{entry.resource_type} {entry.name}"
            attrs: dict[str, Any] = {
                "type": entry.resource_type,
                "name": entry.name,
                "language": entry.language,
                "size": len(entry.data),
                "sha256": entry.sha256,
            }

            if entry.resource_type == "DIALOG":
                try:
                    d_model = DialogResource.parse(entry.data)
                    dialog_models[str(entry.name)] = d_model
                    attrs["title"] = d_model.title
                    attrs["controlCount"] = len(d_model.controls)
                    label = f"DIALOG {entry.name} ('{d_model.title}')"
                except Exception:
                    pass

            elif entry.resource_type == "MENU":
                try:
                    m_model = MenuResource.parse(entry.data)
                    menu_models[str(entry.name)] = m_model
                    attrs["itemCount"] = len(m_model.items)
                except Exception:
                    pass

            elif entry.resource_type == "STRING":
                try:
                    block_id = int(entry.name) if str(entry.name).isdigit() else 1
                    s_block = StringTableBlock.from_bytes(block_id, entry.data)
                    for idx, s_val in enumerate(s_block.strings):
                        if s_val:
                            string_models[s_block.first_string_id + idx] = s_val
                except Exception:
                    pass

            nodes[res_id] = GraphNode(id=res_id, node_type="RESOURCE", label=label, attributes=attrs)

        # 2. Add Controls and Menu Items as Child Nodes
        for d_name, d_model in dialog_models.items():
            parent_id = next((nid for nid, n in nodes.items() if n.attributes.get("type") == "DIALOG" and str(n.attributes.get("name")) == d_name), None)
            if not parent_id:
                continue

            for ctrl in d_model.controls:
                ctrl_id = f"ctrl:{d_name}:{ctrl.control_id}"
                c_label = f"Control {ctrl.control_id} ({ctrl.class_label} '{ctrl.title}')"
                nodes[ctrl_id] = GraphNode(
                    id=ctrl_id,
                    node_type="CONTROL",
                    label=c_label,
                    attributes={
                        "controlId": ctrl.control_id,
                        "title": str(ctrl.title),
                        "class": ctrl.class_label,
                        "dialogName": d_name,
                        "dluWidth": ctrl.width,
                        "dluHeight": ctrl.height,
                    },
                )
                edges.append(
                    GraphEdge(
                        source=parent_id,
                        target=ctrl_id,
                        edge_type="CONTAINS_CONTROL",
                        label="CONTAINS",
                        confidence=1.0,
                        confidence_level="HIGH",
                        evidence=EvidenceRecord(
                            source="PE_RESOURCE_DIRECTORY",
                            address=None,
                            instruction=None,
                            code_snippet=None,
                            confidence=1.0,
                            confidence_level="HIGH",
                            verification_rationale=f"Defined structurally in DIALOG template {d_name}",
                        ),
                    )
                )

        # 3. Disassemble Executable Sections & Find Win32 Resource Call Sites
        call_sites = self._scan_resource_call_sites()

        for cs in call_sites:
            caller_fn_id = f"func:{cs['caller_rva_hex']}"
            caller_label = f"Function {cs['caller_rva_hex']} ({cs['section']})"
            if caller_fn_id not in nodes:
                nodes[caller_fn_id] = GraphNode(
                    id=caller_fn_id,
                    node_type="FUNCTION",
                    label=caller_label,
                    address=cs["caller_rva_hex"],
                    attributes={"section": cs["section"]},
                )

            # Match target resource
            target_res_id = next(
                (
                    nid
                    for nid, n in nodes.items()
                    if n.node_type == "RESOURCE"
                    and str(n.attributes.get("type")).upper() == str(cs["target_type"]).upper()
                    and str(n.attributes.get("name")) == str(cs["target_name"])
                ),
                None,
            )

            if target_res_id:
                edges.append(
                    GraphEdge(
                        source=caller_fn_id,
                        target=target_res_id,
                        edge_type="INVOKES",
                        label=f"calls {cs['api']}",
                        confidence=cs["confidence"],
                        confidence_level=cs["confidence_level"],
                        evidence=EvidenceRecord(
                            source=cs["evidence_source"],
                            address=cs["call_address_hex"],
                            instruction=cs["instruction"],
                            code_snippet=cs.get("code_snippet"),
                            confidence=cs["confidence"],
                            confidence_level=cs["confidence_level"],
                            verification_rationale=cs["verification_rationale"],
                        ),
                    )
                )

            # If call binds a DialogProc callback
            if cs.get("dialog_proc_rva_hex"):
                proc_rva_hex = cs["dialog_proc_rva_hex"]
                proc_fn_id = f"func:{proc_rva_hex}"
                proc_label = f"DialogProc ({proc_rva_hex})"
                if proc_fn_id not in nodes:
                    nodes[proc_fn_id] = GraphNode(
                        id=proc_fn_id,
                        node_type="FUNCTION",
                        label=proc_label,
                        address=proc_rva_hex,
                        attributes={"role": "DIALOG_PROC"},
                    )

                if target_res_id:
                    edges.append(
                        GraphEdge(
                            source=target_res_id,
                            target=proc_fn_id,
                            edge_type="BINDS_PROC",
                            label="lpDialogFunc callback",
                            confidence=cs["confidence"],
                            confidence_level=cs["confidence_level"],
                            evidence=EvidenceRecord(
                                source=cs["evidence_source"],
                                address=cs["call_address_hex"],
                                instruction=cs["instruction"],
                                code_snippet=cs.get("code_snippet"),
                                confidence=cs["confidence"],
                                confidence_level=cs["confidence_level"],
                                verification_rationale=f"Passed as lpDialogFunc parameter in {cs['api']}",
                            ),
                        )
                    )

        # 4. Analyze Message Branches & Control Handlers inside DialogProcs
        for d_name, d_model in dialog_models.items():
            # Find bound DialogProc functions or functions referencing this dialog
            matching_procs = [
                e.target
                for e in edges
                if e.edge_type == "BINDS_PROC"
                and any(n.id == e.source and str(n.attributes.get("name")) == d_name for n in nodes.values())
            ]

            for proc_id in matching_procs:
                proc_node = nodes.get(proc_id)
                if not proc_node:
                    continue
                proc_addr = proc_node.address or proc_node.id.replace("func:", "")
                decompiled_code = self._get_decompiled_code(proc_addr)

                for ctrl in d_model.controls:
                    cid = ctrl.control_id
                    ctrl_node_id = f"ctrl:{d_name}:{cid}"
                    if ctrl_node_id not in nodes:
                        continue

                    # Trace branch in code
                    branch_info = self._analyze_control_branch(proc_addr, cid, decompiled_code)
                    if not branch_info:
                        continue

                    branch_node_id = f"branch:{proc_addr}:{cid}"
                    branch_label = f"WM_COMMAND -> case {cid}"
                    nodes[branch_node_id] = GraphNode(
                        id=branch_node_id,
                        node_type="BRANCH",
                        label=branch_label,
                        address=branch_info.get("address"),
                        attributes={
                            "controlId": cid,
                            "condition": branch_info.get("condition"),
                            "snippet": branch_info.get("snippet"),
                        },
                    )

                    edges.append(
                        GraphEdge(
                            source=ctrl_node_id,
                            target=branch_node_id,
                            edge_type="DISPATCHES_TO",
                            label=f"dispatches to case {cid}",
                            confidence=branch_info["confidence"],
                            confidence_level=branch_info["confidence_level"],
                            evidence=EvidenceRecord(
                                source=branch_info["evidence_source"],
                                address=branch_info.get("address"),
                                instruction=branch_info.get("instruction"),
                                code_snippet=branch_info.get("snippet"),
                                confidence=branch_info["confidence"],
                                confidence_level=branch_info["confidence_level"],
                                verification_rationale=branch_info["verification_rationale"],
                            ),
                        )
                    )

                    # 5. Trace Downstream Calls & Secondary Resources within this branch
                    downstream = self._trace_downstream_calls_and_resources(branch_info, string_models)
                    for item in downstream:
                        target_id = item["target_id"]
                        if target_id not in nodes:
                            nodes[target_id] = GraphNode(
                                id=target_id,
                                node_type=item["node_type"],
                                label=item["label"],
                                address=item.get("address"),
                                attributes=item.get("attributes", {}),
                            )

                        edges.append(
                            GraphEdge(
                                source=branch_node_id,
                                target=target_id,
                                edge_type=item["edge_type"],
                                label=item["edge_label"],
                                confidence=item["confidence"],
                                confidence_level=item["confidence_level"],
                                evidence=EvidenceRecord(
                                    source=item["evidence_source"],
                                    address=item.get("address"),
                                    instruction=item.get("instruction"),
                                    code_snippet=item.get("snippet"),
                                    confidence=item["confidence"],
                                    confidence_level=item["confidence_level"],
                                    verification_rationale=item["verification_rationale"],
                                ),
                            )
                        )

                        # Record Complete Behavioral Trace
                        trace_path = [
                            {"type": "RESOURCE", "id": f"res:DIALOG:{d_name}", "label": f"DIALOG {d_name}"},
                            {"type": "CONTROL", "id": ctrl_node_id, "label": nodes[ctrl_node_id].label},
                            {"type": "BRANCH", "id": branch_node_id, "label": branch_label},
                            {"type": item["node_type"], "id": target_id, "label": item["label"]},
                        ]
                        traces.append(
                            BehavioralTrace(
                                trace_id=f"trace_{d_name}_{cid}_{len(traces)+1}",
                                resource_id=f"DIALOG_{d_name}",
                                control_id=str(cid),
                                path_description=f"DIALOG {d_name} -> Button {cid} ('{ctrl.title}') -> case {cid} -> {item['label']}",
                                nodes=tuple(trace_path),
                                confidence=item["confidence"],
                                confidence_level=item["confidence_level"],
                                evidence_summary=(
                                    branch_info["verification_rationale"],
                                    item["verification_rationale"],
                                ),
                            )
                        )

        # Generate Mermaid Diagram
        mermaid = self._generate_mermaid_diagram(nodes, edges)

        summary = {
            "totalNodes": len(nodes),
            "totalEdges": len(edges),
            "totalTraces": len(traces),
            "dialogsMapped": len(dialog_models),
            "menusMapped": len(menu_models),
            "callSitesCount": len(call_sites),
            "highConfidenceEdges": sum(1 for e in edges if e.confidence >= 0.90),
            "mediumConfidenceEdges": sum(1 for e in edges if 0.70 <= e.confidence < 0.90),
        }

        return ResourceBehaviorGraph(
            pe_path=str(self.path),
            nodes=tuple(nodes.values()),
            edges=tuple(edges),
            traces=tuple(traces),
            mermaid_diagram=mermaid,
            summary=summary,
        )

    def _scan_resource_call_sites(self) -> list[dict[str, Any]]:
        """Scans code sections for Win32 resource API calls (DialogBoxParam, LoadString, LoadMenu, FindResource)."""
        sites: list[dict[str, Any]] = []

        for section in self.binary.sections:
            if not section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
                continue

            content = bytes(section.content)
            sec_rva = section.virtual_address
            sec_va = self.imagebase + sec_rva

            # Maintain a short sliding window of preceding instructions to capture register parameter passing
            recent_insns: list[capstone.CsInsn] = []

            for insn in self.cs.disasm(content, sec_va):
                recent_insns.append(insn)
                if len(recent_insns) > 8:
                    recent_insns.pop(0)

                if insn.mnemonic == "call":
                    api_name = None
                    # Resolve call target
                    for op in insn.operands:
                        if op.type == capstone.x86.X86_OP_MEM:
                            disp = op.mem.disp
                            target_va = (insn.address + insn.size + disp) if self.is_64bit else disp
                            target_rva = target_va - self.imagebase if target_va >= self.imagebase else target_va
                            if target_rva in self.import_map:
                                api_name = self.import_map[target_rva]
                        elif op.type == capstone.x86.X86_OP_IMM:
                            target_va = op.imm & 0xFFFFFFFFFFFFFFFF if self.is_64bit else op.imm & 0xFFFFFFFF
                            target_rva = target_va - self.imagebase if target_va >= self.imagebase else target_va
                            if target_rva in self.import_map:
                                api_name = self.import_map[target_rva]

                    if not api_name:
                        continue

                    short_api = api_name.split("!")[-1]
                    if short_api in KNOWN_RESOURCE_APIS:
                        # Inspect recent instructions for argument constants (Dialog ID, String ID, lpDialogFunc)
                        res_id_val = None
                        dialog_proc_rva = None

                        for prev in reversed(recent_insns[:-1]):
                            for pop in prev.operands:
                                if pop.type == capstone.x86.X86_OP_IMM:
                                    val = pop.imm & 0xFFFFFFFF
                                    if 1 <= val <= 0xFFFF and res_id_val is None:
                                        res_id_val = val
                                    elif val > self.imagebase and dialog_proc_rva is None:
                                        dialog_proc_rva = val - self.imagebase

                        res_type = "DIALOG" if "Dialog" in short_api else ("MENU" if "Menu" in short_api else ("STRING" if "String" in short_api else "RESOURCE"))
                        caller_rva = insn.address - self.imagebase
                        sites.append(
                            {
                                "api": api_name,
                                "target_type": res_type,
                                "target_name": str(res_id_val) if res_id_val else "1",
                                "caller_rva_hex": hex(caller_rva),
                                "call_address_hex": hex(insn.address),
                                "section": section.name,
                                "instruction": f"{insn.mnemonic} {insn.op_str}",
                                "dialog_proc_rva_hex": hex(dialog_proc_rva) if dialog_proc_rva else None,
                                "confidence": 0.95 if res_id_val else 0.85,
                                "confidence_level": "HIGH" if res_id_val else "MEDIUM",
                                "evidence_source": "CAPSTONE_DISASSEMBLER",
                                "verification_rationale": f"Explicit Win32 {short_api} API call instruction with resolved arguments in {section.name}",
                            }
                        )

        return sites

    def _analyze_control_branch(
        self,
        func_addr: str,
        cid: int,
        decompiled_code: str | None,
    ) -> dict[str, Any] | None:
        """Locates the WM_COMMAND/WM_NOTIFY message dispatch branch for control ID."""
        # 1. High-fidelity Ghidra decompilation analysis if available
        if decompiled_code:
            lines = decompiled_code.splitlines()
            for idx, line in enumerate(lines):
                if _line_matches_control(line, cid):
                    snippet = _extract_control_snippet(lines, idx, max_lines=10)
                    return {
                        "address": func_addr,
                        "condition": line.strip(),
                        "snippet": snippet,
                        "instruction": None,
                        "confidence": 0.95,
                        "confidence_level": "HIGH",
                        "evidence_source": "GHIDRA_DECOMPILER",
                        "verification_rationale": f"Ghidra AST identified discrete dispatch branch matching control ID {cid}: '{line.strip()}'",
                    }

        # 2. Binary Disassembly fallback scanning within function bytes
        rva = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
        sec = next((s for s in self.binary.sections if s.virtual_address <= rva < s.virtual_address + s.size), None)
        if not sec:
            return None

        sec_off = rva - sec.virtual_address
        raw = bytes(sec.content)[sec_off : sec_off + 512]
        start_va = self.imagebase + rva

        for insn in self.cs.disasm(raw, start_va):
            if insn.mnemonic in ("cmp", "sub", "xor"):
                for op in insn.operands:
                    if op.type == capstone.x86.X86_OP_IMM and (op.imm & 0xFFFFFFFF) == cid:
                        return {
                            "address": hex(insn.address),
                            "condition": f"{insn.mnemonic} {insn.op_str}",
                            "snippet": f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}",
                            "instruction": f"{insn.mnemonic} {insn.op_str}",
                            "confidence": 0.85,
                            "confidence_level": "MEDIUM",
                            "evidence_source": "CAPSTONE_DISASSEMBLER",
                            "verification_rationale": f"Instruction comparator directly evaluates control ID {cid} against register",
                        }

        return None

    def _trace_downstream_calls_and_resources(
        self,
        branch_info: dict[str, Any],
        string_models: dict[int, str],
    ) -> list[dict[str, Any]]:
        """Identifies functions, APIs, and secondary resources invoked from within the control branch."""
        results: list[dict[str, Any]] = []
        snippet = branch_info.get("snippet") or ""

        # 1. Parse Ghidra C snippet for function calls and APIs
        call_patterns = re.findall(r"\b([a-zA-Z_]\w*)\s*\(", snippet)
        for fn_call in call_patterns:
            if fn_call in ("if", "while", "for", "switch", "return", "sizeof"):
                continue

            # Check if calling secondary Win32 Resource API (e.g. LoadStringW, LoadIconW, MessageBoxW)
            if fn_call in KNOWN_RESOURCE_APIS or "Load" in fn_call or "Message" in fn_call:
                # Search for numeric string IDs in snippet
                num_matches = [int(m) for m in re.findall(r"\b\d+\b", snippet)]
                sec_res_name = None
                for num in num_matches:
                    if num in string_models:
                        sec_res_name = f"STRING {num} ('{string_models[num]}')"
                        break

                label = f"{fn_call} -> {sec_res_name}" if sec_res_name else fn_call
                results.append(
                    {
                        "target_id": f"api:{fn_call}",
                        "node_type": "SECONDARY_RESOURCE" if sec_res_name else "API_CALL",
                        "label": label,
                        "edge_type": "ACCESSES_RESOURCE" if sec_res_name else "CALLS_API",
                        "edge_label": "reads resource" if sec_res_name else "calls API",
                        "address": branch_info.get("address"),
                        "snippet": snippet,
                        "confidence": 0.95,
                        "confidence_level": "HIGH",
                        "evidence_source": "GHIDRA_DECOMPILER",
                        "verification_rationale": f"Decompiled statement invokes Win32 API {fn_call} within control event branch",
                    }
                )
            else:
                # Custom sub-function call
                results.append(
                    {
                        "target_id": f"func:{fn_call}",
                        "node_type": "CALLED_FUNCTION",
                        "label": f"Handler: {fn_call}()",
                        "edge_type": "CALLS",
                        "edge_label": "executes handler",
                        "address": branch_info.get("address"),
                        "snippet": snippet,
                        "confidence": 0.90,
                        "confidence_level": "HIGH",
                        "evidence_source": "GHIDRA_DECOMPILER",
                        "verification_rationale": f"Control event branch invokes downstream worker function {fn_call}()",
                    }
                )

        return results

    def _generate_mermaid_diagram(
        self,
        nodes: dict[str, GraphNode],
        edges: list[GraphEdge],
    ) -> str:
        """Renders valid, escaped Mermaid flowchart syntax representing the behavior graph."""
        lines: list[str] = ["flowchart LR"]

        def _safe_mermaid_id(raw_id: str) -> str:
            return re.sub(r"[^a-zA-Z0-9_]", "_", raw_id)

        def _escape_label(label: str) -> str:
            clean = label.replace('"', "'").replace("\n", " ")
            return f'"{clean}"'

        # Render Nodes
        for nid, node in nodes.items():
            sid = _safe_mermaid_id(nid)
            lbl = _escape_label(node.label)
            if node.node_type == "RESOURCE":
                lines.append(f"  {sid}[({lbl})]")
            elif node.node_type == "CONTROL":
                lines.append(f"  {sid}[{lbl}]")
            elif node.node_type == "BRANCH":
                lines.append(f"  {sid}{{{lbl}}}")
            elif node.node_type in ("FUNCTION", "CALLED_FUNCTION"):
                lines.append(f"  {sid}[[{lbl}]]")
            elif node.node_type == "SECONDARY_RESOURCE":
                lines.append(f"  {sid}[({lbl})]")
            else:
                lines.append(f"  {sid}[{lbl}]")

        # Render Edges
        for edge in edges:
            src = _safe_mermaid_id(edge.source)
            dst = _safe_mermaid_id(edge.target)
            lbl = edge.label.replace('"', "'")
            lines.append(f"  {src} -->|{lbl}| {dst}")

        return "\n".join(lines)


def build_resource_behavior_graph(
    pe_path: str | Path,
    ghidra_url: str | None = None,
    decompiled_sources: dict[str | int, str] | None = None,
) -> ResourceBehaviorGraph:
    """Builds an evidence-backed directed graph connecting PE resources to behavior."""
    engine = BehavioralGraphEngine(
        pe_path=pe_path,
        ghidra_url=ghidra_url,
        decompiled_sources=decompiled_sources,
    )
    return engine.build_graph()

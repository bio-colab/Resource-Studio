from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any

from .parse_cache import shared_parse

_SCHEMA = "resource_studio.static_code_analysis.v1"
_EXECUTE = 0x20000000
_WRITE = 0x80000000


def analyze_static_code(path: Path, *, max_bytes: int = 65536, max_instructions: int = 20000) -> dict[str, Any]:
    """Disassemble a bounded entrypoint slice and build a conservative CFG.

    The function is read-only. Capstone is optional at runtime; an unavailable or
    unsupported decoder produces an explicit status instead of a fake result.
    """

    source = Path(path).expanduser().resolve()
    raw = source.read_bytes()
    base = {
        "schema": _SCHEMA,
        "status": "UNAVAILABLE",
        "source": {"path": str(source), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)},
        "architecture": None,
        "entrypoint": None,
        "disassembly": {"instructionCount": 0, "instructions": [], "truncated": False},
        "cfg": {"nodes": [], "edges": [], "unresolvedTargets": []},
        "unpackingIndicators": [],
        "limitations": [
            "Disassembly starts at the PE entrypoint and is bounded; it is not full recursive code discovery.",
            "CFG edges are derived only from decoded direct branch targets; indirect control flow is unresolved.",
            "Unpacking indicators are static heuristics and do not prove a packer or runtime unpacking.",
        ],
    }
    try:
        import lief
    except ImportError:
        base["limitations"].append("LIEF is unavailable in this environment.")
        return base
    try:
        binary = shared_parse(source)
    except Exception as exc:
        base["status"] = "PARSE_ERROR"
        base["limitations"].append(f"PE parse failed: {exc}")
        return base
    if binary is None or not isinstance(binary, lief.PE.Binary):
        base["status"] = "UNSUPPORTED_FILE"
        return base

    sections = list(binary.sections)
    base["unpackingIndicators"] = _unpacking_indicators(binary, sections, len(raw))
    entry_rva = int(binary.optional_header.addressof_entrypoint)
    section = _section_for_rva(sections, entry_rva)
    machine = str(binary.header.machine).split(".")[-1]
    base["architecture"] = machine
    if section is None or not entry_rva:
        base["status"] = "NO_ENTRYPOINT"
        return base
    section_bytes = bytes(section.content)
    start = max(0, entry_rva - int(section.virtual_address))
    code = section_bytes[start : start + max(1, int(max_bytes))]
    file_offset = int(section.offset) + start
    base["entrypoint"] = {
        "rva": entry_rva,
        "fileOffset": file_offset,
        "section": str(section.name),
        "sectionRva": int(section.virtual_address),
    }
    try:
        import capstone
    except ImportError:
        base["status"] = "DECODER_UNAVAILABLE"
        base["limitations"].append("Install the optional Capstone dependency to enable disassembly and CFG.")
        return base

    decoder = _decoder(capstone, machine)
    if decoder is None:
        base["status"] = "UNSUPPORTED_ARCH"
        base["limitations"].append(f"No bounded decoder mapping is configured for {machine}.")
        return base
    decoder.detail = True
    instructions: list[dict[str, Any]] = []
    decoded = []
    for instruction in decoder.disasm(code, entry_rva):
        if len(decoded) >= max(1, int(max_instructions)):
            base["disassembly"]["truncated"] = True
            break
        decoded.append(instruction)
        instructions.append(
            {
                "rva": int(instruction.address),
                "fileOffset": file_offset + int(instruction.address) - entry_rva,
                "size": int(instruction.size),
                "bytes": bytes(instruction.bytes).hex(),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
            }
        )
    base["disassembly"]["instructionCount"] = len(instructions)
    base["disassembly"]["instructions"] = instructions
    if not decoded:
        base["status"] = "NO_CODE_DECODED"
        return base
    cfg = _build_cfg(decoded, capstone)
    base["cfg"] = cfg
    base["status"] = "ANALYZED"
    return base


def _decoder(capstone: Any, machine: str) -> Any | None:
    if machine == "AMD64":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if machine == "I386":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    if machine == "ARM64":
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    return None


def _section_for_rva(sections: list[Any], rva: int) -> Any | None:
    for section in sections:
        start = int(section.virtual_address)
        end = start + max(int(section.virtual_size), int(section.size), len(section.content))
        if start <= rva < end:
            return section
    return None


def _unpacking_indicators(binary: Any, sections: list[Any], file_size: int) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    executable = [section for section in sections if int(section.characteristics) & _EXECUTE]
    for section in executable:
        raw_size = int(section.size)
        virtual_size = int(section.virtual_size)
        entropy = _entropy(bytes(section.content))
        if raw_size and virtual_size > raw_size * 2 and virtual_size - raw_size >= 4096:
            indicators.append({"kind": "EXECUTABLE_SECTION_EXPANDS_IN_MEMORY", "section": str(section.name), "rawSize": raw_size, "virtualSize": virtual_size, "confidence": "LIMITED"})
        if entropy >= 7.2 and len(section.content) >= 512:
            indicators.append({"kind": "HIGH_ENTROPY_EXECUTABLE_SECTION", "section": str(section.name), "entropy": round(entropy, 4), "confidence": "LIMITED"})
        if int(section.characteristics) & _WRITE:
            indicators.append({"kind": "EXECUTABLE_WRITABLE_SECTION", "section": str(section.name), "confidence": "LIMITED"})
    entry_rva = int(binary.optional_header.addressof_entrypoint)
    entry_section = _section_for_rva(sections, entry_rva)
    if entry_section is not None and not (int(entry_section.characteristics) & _EXECUTE):
        indicators.append({"kind": "ENTRYPOINT_IN_NON_EXECUTABLE_SECTION", "section": str(entry_section.name), "confidence": "HIGH"})
    section_end = max((int(section.offset) + int(section.size) for section in sections), default=0)
    if file_size > section_end:
        indicators.append({"kind": "OVERLAY_DATA", "size": file_size - section_end, "confidence": "LIMITED"})
    return indicators


def _build_cfg(decoded: list[Any], capstone: Any) -> dict[str, Any]:
    by_address = {int(item.address): item for item in decoded}
    boundaries = {int(decoded[0].address)}
    direct_targets: set[int] = set()
    for instruction in decoded:
        target = _direct_target(instruction, capstone)
        if target is not None:
            direct_targets.add(target)
            if target in by_address:
                boundaries.add(target)
        if _is_terminator(instruction):
            next_address = int(instruction.address) + int(instruction.size)
            if next_address in by_address:
                boundaries.add(next_address)
    ordered = sorted(boundaries)
    nodes: list[dict[str, Any]] = []
    node_last: dict[str, Any] = {}
    for index, start in enumerate(ordered):
        next_boundary = ordered[index + 1] if index + 1 < len(ordered) else None
        block = []
        cursor = start
        while cursor in by_address and (next_boundary is None or cursor < next_boundary):
            instruction = by_address[cursor]
            block.append(instruction)
            cursor += int(instruction.size)
            if _is_terminator(instruction):
                break
        if not block:
            continue
        node_id = f"B{len(nodes):04d}"
        nodes.append({"id": node_id, "startRva": start, "endRva": int(block[-1].address) + int(block[-1].size), "instructionCount": len(block)})
        node_last[node_id] = block[-1]
    node_by_address = {int(node["startRva"]): node["id"] for node in nodes}
    edges: set[tuple[str, str, str]] = set()
    unresolved: set[int] = set()
    for index, node in enumerate(nodes):
        last = node_last[node["id"]]
        target = _direct_target(last, capstone)
        if target is not None:
            target_node = node_by_address.get(target)
            if target_node is None:
                unresolved.add(target)
            else:
                edges.add((node["id"], target_node, "branch"))
        if _is_conditional_branch(last):
            fallthrough = int(last.address) + int(last.size)
            fallthrough_node = node_by_address.get(fallthrough)
            if fallthrough_node is not None:
                edges.add((node["id"], fallthrough_node, "fallthrough"))
        elif not _is_terminator(last) and index + 1 < len(nodes):
            edges.add((node["id"], nodes[index + 1]["id"], "fallthrough"))
    return {"nodes": nodes, "edges": [{"from": a, "to": b, "kind": kind} for a, b, kind in sorted(edges)], "unresolvedTargets": sorted(unresolved)}


def _direct_target(instruction: Any, capstone: Any) -> int | None:
    if not instruction.operands or instruction.mnemonic.lower() not in {"call", "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jc", "jcxz", "jg", "jge", "jl", "jle", "jo", "jp", "jpe", "jpo", "js"}:
        return None
    try:
        operand = instruction.operands[0]
        if operand.type == capstone.x86.X86_OP_IMM:
            return int(operand.imm)
    except (AttributeError, IndexError, TypeError):
        return None
    return None


def _is_conditional_branch(instruction: Any) -> bool:
    return instruction.mnemonic.lower().startswith("j") and instruction.mnemonic.lower() not in {"jmp"}


def _is_terminator(instruction: Any) -> bool:
    mnemonic = instruction.mnemonic.lower()
    return mnemonic in {"ret", "retf", "iret", "jmp"} or _is_conditional_branch(instruction)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts if count)


__all__ = ["analyze_static_code"]

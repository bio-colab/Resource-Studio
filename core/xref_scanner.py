from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import capstone
import lief

from .parse_cache import shared_parse
from .resource_reader import ResourceReader
from .string_table import StringTableBlock
from .value_flow_tracker import ValueFlowTracker

KNOWN_RESOURCE_APIS: frozenset[str] = frozenset(
    {
        "FindResourceA",
        "FindResourceW",
        "FindResourceExA",
        "FindResourceExW",
        "LoadStringA",
        "LoadStringW",
        "DialogBoxParamA",
        "DialogBoxParamW",
        "CreateDialogParamA",
        "CreateDialogParamW",
        "DialogBoxIndirectParamA",
        "DialogBoxIndirectParamW",
        "LoadIconA",
        "LoadIconW",
        "LoadCursorA",
        "LoadCursorW",
        "LoadImageA",
        "LoadImageW",
        "LoadBitmapA",
        "LoadBitmapW",
        "LoadMenuA",
        "LoadMenuW",
        "LoadMenuIndirectA",
        "LoadMenuIndirectW",
        "LoadAcceleratorsA",
        "LoadAcceleratorsW",
    }
)


@dataclass(frozen=True)
class CodeReference:
    address: int
    section: str
    mnemonic: str
    operands: str

    @property
    def instruction(self) -> str:
        return f"{self.mnemonic} {self.operands}".strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": hex(self.address),
            "section": self.section,
            "instruction": self.instruction,
        }


@dataclass(frozen=True)
class ResourceXRef:
    resource_type: str
    name: str
    language: int | None
    size: int
    sha256: str
    status: str  # "REFERENCED", "DEAD_ORPHAN", "CONCEALED_SUSPICIOUS"
    references: tuple[CodeReference, ...]

    def to_dict(self, max_references: int = 20) -> dict[str, Any]:
        refs = self.references if max_references <= 0 else self.references[:max_references]
        return {
            "type": self.resource_type,
            "name": self.name,
            "language": self.language,
            "size": self.size,
            "sha256": self.sha256,
            "status": self.status,
            "referenceCount": len(self.references),
            "references": [ref.to_dict() for ref in refs],
            "hasMoreReferences": len(self.references) > len(refs),
        }


@dataclass(frozen=True)
class XRefReport:
    path: str
    machine: str
    has_resource_apis: bool
    imported_resource_apis: tuple[dict[str, str], ...]
    summary: dict[str, int]
    resources: tuple[ResourceXRef, ...]

    def to_dict(self, max_references_per_resource: int = 20) -> dict[str, Any]:
        return {
            "path": self.path,
            "machine": self.machine,
            "hasResourceApis": self.has_resource_apis,
            "importedResourceApis": [dict(api) for api in self.imported_resource_apis],
            "summary": dict(self.summary),
            "resources": [r.to_dict(max_references=max_references_per_resource) for r in self.resources],
        }


def _find_string_in_sections(binary: lief.PE.Binary, target: str) -> list[tuple[str, int]]:
    """Locates occurrences of target string as ASCII or UTF-16LE in PE data/rdata sections."""
    results: list[tuple[str, int]] = []
    if not target or len(target) < 2:
        return results

    ascii_needle = target.encode("ascii", errors="ignore")
    utf16_needle = target.encode("utf-16le")

    for section in binary.sections:
        if not section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ):
            continue
        content = bytes(section.content)
        rva = section.virtual_address

        for needle in (ascii_needle, utf16_needle):
            if len(needle) < 2:
                continue
            idx = 0
            while True:
                pos = content.find(needle, idx)
                if pos == -1:
                    break
                results.append((section.name, rva + pos))
                idx = pos + len(needle)
                if len(results) >= 50:
                    return results
    return results


def scan_pe_xrefs(path: Path) -> XRefReport:
    """Scans executable sections and import table of a PE binary to establish code-to-resource cross references."""
    resolved_path = Path(path).expanduser().resolve()
    if not resolved_path.is_file():
        raise FileNotFoundError(f"PE file not found: {path}")

    binary = shared_parse(resolved_path)
    if binary is None or not isinstance(binary, lief.PE.Binary):
        raise ValueError("File is not a valid Windows PE binary")

    entries = ResourceReader(resolved_path).entries

    # 1. Identify Imported Win32 Resource APIs
    imported_apis: list[dict[str, str]] = []
    iat_map: dict[int, str] = {}
    imagebase = binary.optional_header.imagebase

    for imp in binary.imports:
        for entry in imp.entries:
            if entry.name in KNOWN_RESOURCE_APIS:
                imported_apis.append({"dll": imp.name, "api": entry.name})
                va = entry.iat_address if entry.iat_address >= imagebase else imagebase + entry.iat_address
                iat_map[va] = entry.name

    has_resource_apis = len(imported_apis) > 0

    # 2. Setup Disassembler
    is_64bit = binary.header.machine in (
        lief.PE.Header.MACHINE_TYPES.AMD64,
        lief.PE.Header.MACHINE_TYPES.ARM64,
    )
    mode = capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32
    cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
    cs.detail = True

    # 3. Build Resource Target Map (Numeric IDs, String Names, and StringTable slots)
    numeric_targets: dict[int, list[Any]] = {}
    string_targets: dict[str, list[Any]] = {}
    string_id_to_entry: dict[int, list[Any]] = {}
    entry_to_string_ids: dict[tuple[str, str, int | None], list[int]] = {}

    for entry in entries:
        raw_name = str(entry.name)
        if raw_name.isdigit():
            numeric_targets.setdefault(int(raw_name), []).append(entry)
        else:
            string_targets.setdefault(raw_name.upper(), []).append(entry)

        # Map Win32 STRING table blocks to constituent string IDs
        if entry.resource_type == "STRING" and raw_name.isdigit():
            blk_id = int(raw_name)
            s_ids: list[int] = []
            try:
                blk = StringTableBlock.from_bytes(blk_id, entry.data)
                for idx, text in enumerate(blk.strings):
                    if text:
                        sid = blk.first_string_id + idx
                        s_ids.append(sid)
                        string_id_to_entry.setdefault(sid, []).append(entry)
            except Exception:
                for sid in range((blk_id - 1) * 16 + 1, blk_id * 16 + 1):
                    s_ids.append(sid)
                    string_id_to_entry.setdefault(sid, []).append(entry)
            entry_to_string_ids[entry.key] = s_ids

    # 4. Disassemble Code Sections and Collect Immediate & Value-Flow Operands
    immediate_refs: dict[int, list[CodeReference]] = {}
    string_id_refs: dict[int, list[CodeReference]] = {}

    NOISE_SHIFTS = frozenset({"shr", "shl", "sar", "sal", "ror", "rol", "rcr", "rcl"})
    NOISE_LOGIC = frozenset({"and", "test", "bt", "bts", "btr", "btc"})

    for section in binary.sections:
        if not section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
            continue
        content = bytes(section.content)
        sec_rva = section.virtual_address
        sec_va = imagebase + sec_rva

        tracker = ValueFlowTracker(is_64bit=is_64bit)

        for insn in cs.disasm(content, sec_va):
            mnemonic = insn.mnemonic.lower()
            tracker.process_instruction(insn)

            # A. Value-flow call resolution (e.g. call qword ptr [LoadStringW])
            if mnemonic == "call":
                target_va = None
                for op in insn.operands:
                    if op.type == capstone.x86.X86_OP_MEM:
                        if is_64bit:
                            target_va = (insn.address + insn.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                        else:
                            target_va = op.mem.disp & 0xFFFFFFFF
                    elif op.type == capstone.x86.X86_OP_IMM:
                        target_va = op.imm & 0xFFFFFFFF

                if target_va in iat_map:
                    api_name = iat_map[target_va]
                    binding = tracker.resolve_api_call(api_name, insn.address)
                    if binding and binding.target_id > 0:
                        bid = binding.target_id
                        ref = CodeReference(
                            address=insn.address,
                            section=section.name,
                            mnemonic=f"call:{api_name}",
                            operands=f"id={bid} [{' -> '.join(binding.evidence_instructions)}]",
                        )
                        if bid in numeric_targets:
                            immediate_refs.setdefault(bid, []).append(ref)
                        if bid in string_id_to_entry:
                            string_id_refs.setdefault(bid, []).append(ref)

            elif mnemonic in ("ret", "jmp"):
                tracker.reset_block()

            # B. Immediate operands
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    imm_val = op.imm & 0xFFFFFFFF
                    # Filter out shift count operations and small logic masks
                    if mnemonic in NOISE_SHIFTS:
                        continue
                    if imm_val <= 8 and mnemonic in NOISE_LOGIC:
                        continue

                    if imm_val in numeric_targets:
                        ref = CodeReference(
                            address=insn.address,
                            section=section.name,
                            mnemonic=insn.mnemonic,
                            operands=insn.op_str,
                        )
                        immediate_refs.setdefault(imm_val, []).append(ref)

                    if imm_val in string_id_to_entry:
                        ref = CodeReference(
                            address=insn.address,
                            section=section.name,
                            mnemonic=f"{insn.mnemonic}:str_id={imm_val}",
                            operands=insn.op_str,
                        )
                        string_id_refs.setdefault(imm_val, []).append(ref)

                # C. Effective LEA displacement (e.g. lea edx, [rax + 0x71])
                elif op.type == capstone.x86.X86_OP_MEM and mnemonic == "lea":
                    mem = op.mem
                    disp = mem.disp & 0xFFFFFFFF
                    if disp in numeric_targets:
                        ref = CodeReference(
                            address=insn.address,
                            section=section.name,
                            mnemonic="lea:res_id",
                            operands=insn.op_str,
                        )
                        immediate_refs.setdefault(disp, []).append(ref)
                    if disp in string_id_to_entry:
                        ref = CodeReference(
                            address=insn.address,
                            section=section.name,
                            mnemonic=f"lea:str_id={disp}",
                            operands=insn.op_str,
                        )
                        string_id_refs.setdefault(disp, []).append(ref)

    # 5. Scan Read-Only Data Sections for Resource & String ID Tables
    data_table_refs: dict[int, list[CodeReference]] = {}
    SKIP_DATA_SECTIONS = frozenset({".rsrc", ".reloc", ".pdata", ".xdata", ".CRT", ".tls", ".bss", ".idata"})

    for section in binary.sections:
        sec_name = section.name
        if sec_name in SKIP_DATA_SECTIONS or sec_name.startswith("/") or sec_name.startswith(".debug"):
            continue
        if section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_DISCARDABLE):
            continue
        if not section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ):
            continue
        if section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
            continue

        sec_bytes = bytes(section.content)
        sec_rva = section.virtual_address

        # Check numeric targets (IDs >= 100 to prevent small integer false matches in data)
        for num_id in numeric_targets:
            if num_id >= 100:
                dw = num_id.to_bytes(4, "little")
                pos = 0
                match_count = 0
                while match_count < 10:
                    pos = sec_bytes.find(dw, pos)
                    if pos == -1:
                        break
                    ref = CodeReference(
                        address=imagebase + sec_rva + pos,
                        section=section.name,
                        mnemonic="data_table_ref",
                        operands=f"DWORD {num_id}",
                    )
                    data_table_refs.setdefault(num_id, []).append(ref)
                    pos += 4
                    match_count += 1

        # Check string IDs in data tables (only >= 100 to avoid small integer constants)
        for sid in string_id_to_entry:
            if sid >= 100:
                dw = sid.to_bytes(4, "little")
                pos = sec_bytes.find(dw)
                if pos != -1:
                    ref = CodeReference(
                        address=imagebase + sec_rva + pos,
                        section=section.name,
                        mnemonic="data_table_ref",
                        operands=f"DWORD {sid}",
                    )
                    data_table_refs.setdefault(sid, []).append(ref)
                else:
                    # Also check 16-bit word in data tables
                    w = sid.to_bytes(2, "little")
                    pos = sec_bytes.find(w)
                    if pos != -1:
                        ref = CodeReference(
                            address=imagebase + sec_rva + pos,
                            section=section.name,
                            mnemonic="data_table_ref",
                            operands=f"WORD {sid}",
                        )
                        data_table_refs.setdefault(sid, []).append(ref)

    # 6. String References Search
    named_refs: dict[str, list[CodeReference]] = {}
    for name in string_targets:
        hits = _find_string_in_sections(binary, name)
        for sec_name, rva in hits:
            ref = CodeReference(
                address=imagebase + rva,
                section=sec_name,
                mnemonic="data_ref",
                operands=f'"{name}"',
            )
            named_refs.setdefault(name, []).append(ref)

    # 7. Categorize each Resource Entry
    categorized: list[ResourceXRef] = []
    referenced_count = 0
    dead_count = 0
    suspicious_count = 0

    for entry in entries:
        raw_name = str(entry.name)
        refs: list[CodeReference] = []

        if raw_name.isdigit():
            num_id = int(raw_name)
            refs = list(immediate_refs.get(num_id, []))
            refs.extend(data_table_refs.get(num_id, []))

            # Include references to string IDs belonging to this block
            if entry.resource_type == "STRING":
                for s_id in entry_to_string_ids.get(entry.key, []):
                    refs.extend(string_id_refs.get(s_id, []))
                    refs.extend(data_table_refs.get(s_id, []))
        else:
            refs = list(named_refs.get(raw_name.upper(), []))

        # Classification rule
        if refs:
            status = "REFERENCED"
            referenced_count += 1
        else:
            # If large raw RCDATA or custom type with no standard references
            if entry.resource_type in ("RCDATA", "10") and len(entry.data) > 1024:
                status = "CONCEALED_SUSPICIOUS"
                suspicious_count += 1
            else:
                status = "DEAD_ORPHAN"
                dead_count += 1

        categorized.append(
            ResourceXRef(
                resource_type=entry.resource_type,
                name=entry.name,
                language=entry.language,
                size=len(entry.data),
                sha256=entry.sha256,
                status=status,
                references=tuple(refs),
            )
        )

    machine_name = "x64" if is_64bit else "x86"
    summary = {
        "totalResources": len(entries),
        "referenced": referenced_count,
        "deadOrphans": dead_count,
        "suspicious": suspicious_count,
    }

    return XRefReport(
        path=str(resolved_path),
        machine=machine_name,
        has_resource_apis=has_resource_apis,
        imported_resource_apis=tuple(imported_apis),
        summary=summary,
        resources=tuple(categorized),
    )

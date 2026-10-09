from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import capstone
import lief

from .parse_cache import shared_parse
from .resource_reader import ResourceReader

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": hex(self.address),
            "section": self.section,
            "instruction": f"{self.mnemonic} {self.operands}".strip(),
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
    for imp in binary.imports:
        for entry in imp.entries:
            if entry.name in KNOWN_RESOURCE_APIS:
                imported_apis.append({"dll": imp.name, "api": entry.name})

    has_resource_apis = len(imported_apis) > 0

    # 2. Setup Disassembler
    is_64bit = binary.header.machine in (
        lief.PE.Header.MACHINE_TYPES.AMD64,
        lief.PE.Header.MACHINE_TYPES.ARM64,
    )
    mode = capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32
    cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
    cs.detail = True

    # 3. Build Resource Target Map (Numeric IDs and String Names)
    numeric_targets: dict[int, list[Any]] = {}
    string_targets: dict[str, list[Any]] = {}

    for entry in entries:
        raw_name = str(entry.name)
        if raw_name.isdigit():
            numeric_targets.setdefault(int(raw_name), []).append(entry)
        else:
            string_targets.setdefault(raw_name.upper(), []).append(entry)

    # 4. Disassemble Code Sections and Collect Immediate Operands
    imagebase = binary.optional_header.imagebase
    immediate_refs: dict[int, list[CodeReference]] = {}

    for section in binary.sections:
        if not section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
            continue
        content = bytes(section.content)
        sec_rva = section.virtual_address
        sec_va = imagebase + sec_rva

        for insn in cs.disasm(content, sec_va):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    imm_val = op.imm & 0xFFFFFFFF
                    if imm_val in numeric_targets:
                        ref = CodeReference(
                            address=insn.address,
                            section=section.name,
                            mnemonic=insn.mnemonic,
                            operands=insn.op_str,
                        )
                        immediate_refs.setdefault(imm_val, []).append(ref)

    # 5. String References Search
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

    # 6. Categorize each Resource Entry
    categorized: list[ResourceXRef] = []
    referenced_count = 0
    dead_count = 0
    suspicious_count = 0

    for entry in entries:
        raw_name = str(entry.name)
        refs: list[CodeReference] = []

        if raw_name.isdigit():
            num_id = int(raw_name)
            refs = immediate_refs.get(num_id, [])
        else:
            refs = named_refs.get(raw_name.upper(), [])

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

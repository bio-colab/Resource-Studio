from __future__ import annotations

import difflib
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import capstone
import lief

from .dialog_resources import DialogResource
from .menu_resources import MenuResource
from .parse_cache import shared_parse
from .resource_reader import ResourceReader
from .string_table import StringTableBlock
from .xref_scanner import KNOWN_RESOURCE_APIS


@dataclass(frozen=True)
class FunctionSignature:
    """Represents an analyzed binary function with normalized structural features."""

    rva: int
    size: int
    name: str
    section: str
    normalized_mnemonics: tuple[str, ...]
    normalized_instructions: tuple[str, ...]
    api_calls: frozenset[str]
    immediates: frozenset[int]
    referenced_strings: frozenset[str]
    referenced_resources: frozenset[int]
    decompiled_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rva": hex(self.rva),
            "size": self.size,
            "name": self.name,
            "section": self.section,
            "instructionCount": len(self.normalized_instructions),
            "apiCalls": sorted(self.api_calls),
            "immediatesCount": len(self.immediates),
            "referencedStrings": sorted(self.referenced_strings)[:10],
            "referencedResources": sorted(self.referenced_resources),
            "hasDecompiledCode": bool(self.decompiled_code),
        }


@dataclass(frozen=True)
class FunctionMatch:
    """Represents equivalence and evolution between a function in the old PE and new PE."""

    old_function: FunctionSignature | None
    new_function: FunctionSignature | None
    similarity: float
    status: str  # "IDENTICAL", "RELOCATED_ONLY", "EQUIVALENT_MODIFIED", "ADDED", "REMOVED"
    address_delta: int | None
    constants_changed: tuple[int, ...]
    api_calls_added: tuple[str, ...]
    api_calls_removed: tuple[str, ...]
    code_diff_snippet: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "similarity": round(self.similarity, 3),
            "addressDelta": self.address_delta,
            "oldRva": hex(self.old_function.rva) if self.old_function else None,
            "newRva": hex(self.new_function.rva) if self.new_function else None,
            "oldName": self.old_function.name if self.old_function else None,
            "newName": self.new_function.name if self.new_function else None,
            "constantsChanged": list(self.constants_changed),
            "apiCallsAdded": list(self.api_calls_added),
            "apiCallsRemoved": list(self.api_calls_removed),
            "codeDiffSnippet": self.code_diff_snippet,
        }


@dataclass(frozen=True)
class ResourceDifference:
    """Detailed difference in resources, dialog controls, menus, or strings."""

    resource_type: str  # "DIALOG", "MENU", "STRING", etc.
    resource_name: str
    item_id: int | str
    item_label: str
    change_type: str  # "ADDED", "REMOVED", "MODIFIED"
    details_before: dict[str, Any] | None = None
    details_after: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "resourceType": self.resource_type,
            "resourceName": self.resource_name,
            "itemId": self.item_id,
            "itemLabel": self.item_label,
            "changeType": self.change_type,
            "detailsBefore": self.details_before,
            "detailsAfter": self.details_after,
        }


@dataclass(frozen=True)
class CausalCorrelation:
    """Direct causal link explaining a resource/UI change via a code-level change."""

    target: str
    change_type: str
    resource_change: str
    code_explanation: str
    related_old_rva: str | None
    related_new_rva: str | None
    related_function_name: str | None
    confidence: str  # "HIGH", "MEDIUM", "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "changeType": self.change_type,
            "resourceChange": self.resource_change,
            "codeExplanation": self.code_explanation,
            "relatedOldRva": self.related_old_rva,
            "relatedNewRva": self.related_new_rva,
            "relatedFunctionName": self.related_function_name,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class BehavioralDiffReport:
    """Comprehensive behavioral comparison report between two PE binaries."""

    old_path: str
    new_path: str
    files_identical: bool
    summary: dict[str, Any]
    function_matches: tuple[FunctionMatch, ...]
    resource_differences: tuple[ResourceDifference, ...]
    causal_correlations: tuple[CausalCorrelation, ...]
    human_summary: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "oldPath": self.old_path,
            "newPath": self.new_path,
            "filesIdentical": self.files_identical,
            "summary": self.summary,
            "functionMatches": [m.to_dict() for m in self.function_matches],
            "resourceDifferences": [r.to_dict() for r in self.resource_differences],
            "causalCorrelations": [c.to_dict() for c in self.causal_correlations],
            "humanSummary": list(self.human_summary),
        }


class FunctionExtractor:
    """Extracts function boundaries, disassembles instructions, and collects semantic signatures."""

    def __init__(self, binary_path: Path) -> None:
        self.path = Path(binary_path).expanduser().resolve()
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
        self.import_map = self._build_import_map()
        self.string_literals = self._build_string_map()

    def _build_import_map(self) -> dict[int, str]:
        """Maps IAT RVA/addresses to 'DLL!APIName'."""
        mapping: dict[int, str] = {}
        for imp in self.binary.imports:
            dll_name = imp.name
            for entry in imp.entries:
                if entry.name:
                    sym = f"{dll_name}!{entry.name}"
                    mapping[entry.iat_address] = sym
                    # Also map as RVA relative to imagebase if iat_address is a VA
                    if entry.iat_address >= self.imagebase:
                        mapping[entry.iat_address - self.imagebase] = sym
        return mapping

    def _build_string_map(self) -> dict[int, str]:
        """Extracts ASCII and UTF-16LE string literals located in data sections."""
        strings: dict[int, str] = {}
        for section in self.binary.sections:
            if not section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ):
                continue
            content = bytes(section.content)
            sec_rva = section.virtual_address

            # Find ASCII strings (length >= 4)
            for m in re.finditer(b"[\x20-\x7e]{4,}", content):
                val = m.group().decode("ascii", errors="ignore")
                strings[sec_rva + m.start()] = val

            # Find UTF-16LE strings (length >= 4 chars)
            for m in re.finditer(b"(?:[\x20-\x7e]\x00){4,}", content):
                try:
                    val = m.group().decode("utf-16le")
                    strings[sec_rva + m.start()] = val
                except UnicodeDecodeError:
                    pass
        return strings

    def discover_function_spans(self) -> list[tuple[int, int, str]]:
        """Identifies function start RVA, end RVA, and best known symbol name."""
        spans: list[tuple[int, int, str]] = []

        # 1. Parse .pdata section on x64 binaries if available
        pdata_sec = next((s for s in self.binary.sections if s.name.lower() == ".pdata"), None)
        if pdata_sec and self.is_64bit:
            raw = bytes(pdata_sec.content)
            for i in range(0, len(raw), 12):
                if i + 12 <= len(raw):
                    b_rva, e_rva, _ = struct.unpack_from("<III", raw, i)
                    if b_rva != 0 and e_rva > b_rva:
                        spans.append((b_rva, e_rva, f"sub_{b_rva:X}"))

        # 2. Check exported functions
        for exp in self.binary.exported_functions if hasattr(self.binary, "exported_functions") else self.binary.exports:
            rva = exp.address
            name = exp.name or f"export_{rva:X}"
            if not any(s[0] == rva for s in spans):
                spans.append((rva, rva + 0x80, name))

        # 3. Check Entry Point
        ep = self.binary.optional_header.addressof_entrypoint
        if ep and not any(s[0] == ep for s in spans):
            spans.append((ep, ep + 0x100, "entrypoint"))

        # 4. If no functions found, sweep executable sections for prologues & call targets
        if len(spans) < 2:
            spans.extend(self._sweep_executable_sections())

        # Sort and deduplicate by start RVA
        seen_rvas: set[int] = set()
        unique_spans: list[tuple[int, int, str]] = []
        for b_rva, e_rva, name in sorted(spans, key=lambda s: s[0]):
            if b_rva not in seen_rvas:
                seen_rvas.add(b_rva)
                unique_spans.append((b_rva, e_rva, name))

        return unique_spans

    def _sweep_executable_sections(self) -> list[tuple[int, int, str]]:
        """Disassembles executable sections searching for function prologues and returns."""
        discovered: list[tuple[int, int, str]] = []
        for section in self.binary.sections:
            if not section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
                continue
            content = bytes(section.content)
            sec_rva = section.virtual_address

            # Scan for x86/x64 prologues
            # e.g., push rbp/ebp, sub rsp/esp
            prologue_offsets: list[int] = []
            for i in range(len(content) - 4):
                b = content[i : i + 4]
                if b[:3] in (b"\x55\x89\xe5", b"\x55\x8b\xec"):  # push ebp; mov ebp, esp
                    prologue_offsets.append(i)
                elif b[:3] == b"\x48\x83\xec":  # sub rsp, imm
                    prologue_offsets.append(i)
                elif b[:1] == b"\x55" and (i == 0 or content[i - 1] in (0xCC, 0x90, 0xC3)):  # push rbp/ebp aligned
                    prologue_offsets.append(i)

            for idx, off in enumerate(prologue_offsets):
                start_rva = sec_rva + off
                # End RVA is either next prologue or find ret (0xC3)
                next_off = prologue_offsets[idx + 1] if idx + 1 < len(prologue_offsets) else len(content)
                ret_pos = content.find(b"\xc3", off, next_off)
                end_rva = sec_rva + (ret_pos + 1 if ret_pos != -1 else min(off + 0x100, next_off))
                discovered.append((start_rva, max(end_rva, start_rva + 8), f"sub_{start_rva:X}"))

        return discovered

    def analyze_function(
        self,
        start_rva: int,
        end_rva: int,
        name: str,
        decompiled_code: str | None = None,
    ) -> FunctionSignature | None:
        """Disassembles and generates FunctionSignature for the given range."""
        sec = next((s for s in self.binary.sections if s.virtual_address <= start_rva < s.virtual_address + s.size), None)
        if not sec:
            return None

        sec_offset = start_rva - sec.virtual_address
        length = min(end_rva - start_rva, sec.size - sec_offset)
        if length <= 0:
            return None

        code_bytes = bytes(sec.content)[sec_offset : sec_offset + length]
        start_va = self.imagebase + start_rva

        mnemonics: list[str] = []
        instructions: list[str] = []
        apis: set[str] = set()
        immediates: set[int] = set()
        strings: set[str] = set()
        resources: set[int] = set()

        for insn in self.cs.disasm(code_bytes, start_va):
            mnem = insn.mnemonic.lower()
            mnemonics.append(mnem)

            # Normalize operands
            op_str = insn.op_str
            # Check for API calls
            if mnem == "call":
                # Check direct address or displacement
                for op in insn.operands:
                    if op.type == capstone.x86.X86_OP_MEM:
                        disp = op.mem.disp
                        # Check RIP-relative displacement on x64
                        target_va = (insn.address + insn.size + disp) if self.is_64bit else disp
                        target_rva = target_va - self.imagebase if target_va >= self.imagebase else target_va
                        if target_rva in self.import_map:
                            api = self.import_map[target_rva]
                            apis.add(api)
                            op_str = f"[{api}]"
                    elif op.type == capstone.x86.X86_OP_IMM:
                        imm_va = op.imm & 0xFFFFFFFFFFFFFFFF if self.is_64bit else op.imm & 0xFFFFFFFF
                        imm_rva = imm_va - self.imagebase if imm_va >= self.imagebase else imm_va
                        if imm_rva in self.import_map:
                            api = self.import_map[imm_rva]
                            apis.add(api)
                            op_str = f"[{api}]"

            # Check immediate constants and resource IDs
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    val = op.imm & 0xFFFFFFFF
                    if val != 0 and val < 0x1000000:
                        immediates.add(val)
                        if 1 <= val <= 0xFFFF:
                            resources.add(val)
                elif op.type == capstone.x86.X86_OP_MEM:
                    disp = op.mem.disp
                    target_va = (insn.address + insn.size + disp) if self.is_64bit else disp
                    target_rva = target_va - self.imagebase if target_va >= self.imagebase else target_va
                    if target_rva in self.string_literals:
                        strings.add(self.string_literals[target_rva])

            norm_line = f"{mnem} {op_str}".strip()
            instructions.append(norm_line)

        return FunctionSignature(
            rva=start_rva,
            size=length,
            name=name,
            section=sec.name,
            normalized_mnemonics=tuple(mnemonics),
            normalized_instructions=tuple(instructions),
            api_calls=frozenset(apis),
            immediates=frozenset(immediates),
            referenced_strings=frozenset(strings),
            referenced_resources=frozenset(resources),
            decompiled_code=decompiled_code,
        )

    def extract_all_functions(
        self,
        decompiled_map: dict[str | int, str] | None = None,
    ) -> list[FunctionSignature]:
        """Extracts and analyzes all discovered functions in the binary."""
        spans = self.discover_function_spans()
        functions: list[FunctionSignature] = []
        dec_map = decompiled_map or {}

        for b_rva, e_rva, name in spans:
            dec = dec_map.get(b_rva) or dec_map.get(hex(b_rva)) or dec_map.get(name)
            sig = self.analyze_function(b_rva, e_rva, name, decompiled_code=dec)
            if sig and sig.normalized_instructions:
                functions.append(sig)

        return functions


class FunctionMatcher:
    """Matches equivalent functions between two PE versions even with shifted addresses or modified constants."""

    @staticmethod
    def _compute_sequence_similarity(seq1: tuple[str, ...], seq2: tuple[str, ...]) -> float:
        """Calculates SequenceMatcher ratio between two normalized instruction or mnemonic lists."""
        if not seq1 and not seq2:
            return 1.0
        if not seq1 or not seq2:
            return 0.0
        # Use opcode n-grams for fast, resilient structural matching
        n = 3
        if len(seq1) >= n and len(seq2) >= n:
            grams1 = {seq1[i : i + n] for i in range(len(seq1) - n + 1)}
            grams2 = {seq2[i : i + n] for i in range(len(seq2) - n + 1)}
            intersection = grams1 & grams2
            union = grams1 | grams2
            return len(intersection) / len(union) if union else 1.0
        matcher = difflib.SequenceMatcher(None, seq1, seq2, autojunk=False)
        return matcher.ratio()

    @staticmethod
    def _jaccard(s1: frozenset[Any], s2: frozenset[Any]) -> float:
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0
        return len(s1 & s2) / len(s1 | s2)

    def calculate_similarity(self, f1: FunctionSignature, f2: FunctionSignature) -> float:
        """Computes composite similarity score between two functions."""
        # 1. Exact symbol match
        if f1.name == f2.name and not f1.name.startswith("sub_"):
            return 1.0

        # 2. Structural opcode sequence similarity (weight 50%)
        sim_mnemonics = self._compute_sequence_similarity(f1.normalized_mnemonics, f2.normalized_mnemonics)

        # 3. External API calls similarity (weight 25%)
        sim_apis = self._jaccard(f1.api_calls, f2.api_calls)

        # 4. Immediate constants similarity (weight 15%)
        sim_immediates = self._jaccard(f1.immediates, f2.immediates)

        # 5. String references similarity (weight 10%)
        sim_strings = self._jaccard(f1.referenced_strings, f2.referenced_strings)

        score = (
            0.50 * sim_mnemonics
            + 0.25 * sim_apis
            + 0.15 * sim_immediates
            + 0.10 * sim_strings
        )

        # Optional decompiled code boost
        if f1.decompiled_code and f2.decompiled_code:
            dec1_tokens = re.findall(r"\b[a-zA-Z_]\w*\b", f1.decompiled_code)
            dec2_tokens = re.findall(r"\b[a-zA-Z_]\w*\b", f2.decompiled_code)
            sim_dec = difflib.SequenceMatcher(None, dec1_tokens, dec2_tokens).ratio()
            score = 0.5 * score + 0.5 * sim_dec

        return min(max(score, 0.0), 1.0)

    def match_functions(
        self,
        old_funcs: list[FunctionSignature],
        new_funcs: list[FunctionSignature],
        threshold: float = 0.55,
    ) -> list[FunctionMatch]:
        """Performs optimal bipartite matching of functions across binary versions."""
        matches: list[FunctionMatch] = []
        unmatched_new = set(range(len(new_funcs)))
        unmatched_old = set(range(len(old_funcs)))

        # Precalculate candidate pairs and sort descending by similarity
        candidates: list[tuple[float, int, int]] = []
        for i, f_old in enumerate(old_funcs):
            for j, f_new in enumerate(new_funcs):
                sim = self.calculate_similarity(f_old, f_new)
                if sim >= threshold:
                    candidates.append((sim, i, j))

        candidates.sort(key=lambda c: c[0], reverse=True)

        matched_old: set[int] = set()
        matched_new: set[int] = set()

        for sim, i, j in candidates:
            if i in matched_old or j in matched_new:
                continue

            matched_old.add(i)
            matched_new.add(j)
            unmatched_old.discard(i)
            unmatched_new.discard(j)

            f_old = old_funcs[i]
            f_new = new_funcs[j]
            delta = f_new.rva - f_old.rva

            # Determine evolution status
            constants_changed = tuple(sorted((f_old.immediates ^ f_new.immediates) & (f_old.referenced_resources | f_new.referenced_resources)))
            apis_added = tuple(sorted(f_new.api_calls - f_old.api_calls))
            apis_removed = tuple(sorted(f_old.api_calls - f_new.api_calls))

            if sim >= 0.99 and delta == 0 and not constants_changed and not apis_added and not apis_removed:
                status = "IDENTICAL"
            elif sim >= 0.88 and not constants_changed and not apis_added and not apis_removed:
                status = "RELOCATED_ONLY"
            else:
                status = "EQUIVALENT_MODIFIED"

            # Snippet diff
            diff_lines = list(
                difflib.unified_diff(
                    list(f_old.normalized_instructions[:40]),
                    list(f_new.normalized_instructions[:40]),
                    fromfile=f"old_{hex(f_old.rva)}",
                    tofile=f"new_{hex(f_new.rva)}",
                    lineterm="",
                )
            )
            diff_snippet = "\n".join(diff_lines[:25]) if diff_lines else None

            matches.append(
                FunctionMatch(
                    old_function=f_old,
                    new_function=f_new,
                    similarity=sim,
                    status=status,
                    address_delta=delta,
                    constants_changed=constants_changed,
                    api_calls_added=apis_added,
                    api_calls_removed=apis_removed,
                    code_diff_snippet=diff_snippet,
                )
            )

        # Record removed functions
        for i in unmatched_old:
            f_old = old_funcs[i]
            matches.append(
                FunctionMatch(
                    old_function=f_old,
                    new_function=None,
                    similarity=0.0,
                    status="REMOVED",
                    address_delta=None,
                    constants_changed=(),
                    api_calls_added=(),
                    api_calls_removed=tuple(sorted(f_old.api_calls)),
                    code_diff_snippet=None,
                )
            )

        # Record added functions
        for j in unmatched_new:
            f_new = new_funcs[j]
            matches.append(
                FunctionMatch(
                    old_function=None,
                    new_function=f_new,
                    similarity=0.0,
                    status="ADDED",
                    address_delta=None,
                    constants_changed=(),
                    api_calls_added=tuple(sorted(f_new.api_calls)),
                    api_calls_removed=(),
                    code_diff_snippet=None,
                )
            )

        return matches


class ResourceComparator:
    """Performs deep behavioral inspection on Dialogs, Menus, Strings, and controls between PE versions."""

    @staticmethod
    def extract_dialog_differences(old_path: Path, new_path: Path) -> list[ResourceDifference]:
        differences: list[ResourceDifference] = []
        old_entries = {e.name: e for e in ResourceReader(old_path).entries if e.resource_type == "DIALOG"}
        new_entries = {e.name: e for e in ResourceReader(new_path).entries if e.resource_type == "DIALOG"}

        for name in sorted(set(old_entries) | set(new_entries), key=str):
            old_e = old_entries.get(name)
            new_e = new_entries.get(name)

            if old_e is None and new_e is not None:
                try:
                    d_new = DialogResource.parse(new_e.data)
                    differences.append(
                        ResourceDifference(
                            resource_type="DIALOG",
                            resource_name=str(name),
                            item_id=str(name),
                            item_label=d_new.title or f"Dialog_{name}",
                            change_type="ADDED",
                            details_after=d_new.to_dict(),
                        )
                    )
                except Exception:
                    pass
                continue

            if new_e is None and old_e is not None:
                try:
                    d_old = DialogResource.parse(old_e.data)
                    differences.append(
                        ResourceDifference(
                            resource_type="DIALOG",
                            resource_name=str(name),
                            item_id=str(name),
                            item_label=d_old.title or f"Dialog_{name}",
                            change_type="REMOVED",
                            details_before=d_old.to_dict(),
                        )
                    )
                except Exception:
                    pass
                continue

            if old_e is not None and new_e is not None and old_e.data != new_e.data:
                try:
                    d_old = DialogResource.parse(old_e.data)
                    d_new = DialogResource.parse(new_e.data)
                except Exception:
                    continue

                # Compare Dialog properties
                if d_old.title != d_new.title or (d_old.width, d_old.height) != (d_new.width, d_new.height):
                    differences.append(
                        ResourceDifference(
                            resource_type="DIALOG",
                            resource_name=str(name),
                            item_id=str(name),
                            item_label=f"Dialog Title/Geometry: '{d_old.title}' -> '{d_new.title}'",
                            change_type="MODIFIED",
                            details_before={"title": d_old.title, "dimensions": [d_old.width, d_old.height]},
                            details_after={"title": d_new.title, "dimensions": [d_new.width, d_new.height]},
                        )
                    )

                # Compare Controls
                old_ctls = {c.control_id: c for c in d_old.controls}
                new_ctls = {c.control_id: c for c in d_new.controls}

                for cid in sorted(set(old_ctls) | set(new_ctls)):
                    oc = old_ctls.get(cid)
                    nc = new_ctls.get(cid)
                    if oc is None and nc is not None:
                        differences.append(
                            ResourceDifference(
                                resource_type="DIALOG_CONTROL",
                                resource_name=str(name),
                                item_id=cid,
                                item_label=f"{nc.class_label} '{nc.title}'",
                                change_type="ADDED",
                                details_after=nc.to_dict(),
                            )
                        )
                    elif nc is None and oc is not None:
                        differences.append(
                            ResourceDifference(
                                resource_type="DIALOG_CONTROL",
                                resource_name=str(name),
                                item_id=cid,
                                item_label=f"{oc.class_label} '{oc.title}'",
                                change_type="REMOVED",
                                details_before=oc.to_dict(),
                            )
                        )
                    elif oc is not None and nc is not None and oc.to_dict() != nc.to_dict():
                        differences.append(
                            ResourceDifference(
                                resource_type="DIALOG_CONTROL",
                                resource_name=str(name),
                                item_id=cid,
                                item_label=f"{nc.class_label} '{oc.title}' -> '{nc.title}'",
                                change_type="MODIFIED",
                                details_before=oc.to_dict(),
                                details_after=nc.to_dict(),
                            )
                        )

        return differences

    @staticmethod
    def extract_menu_differences(old_path: Path, new_path: Path) -> list[ResourceDifference]:
        differences: list[ResourceDifference] = []
        old_entries = {e.name: e for e in ResourceReader(old_path).entries if e.resource_type == "MENU"}
        new_entries = {e.name: e for e in ResourceReader(new_path).entries if e.resource_type == "MENU"}

        for name in sorted(set(old_entries) | set(new_entries), key=str):
            old_e = old_entries.get(name)
            new_e = new_entries.get(name)

            if old_e is None and new_e is not None:
                try:
                    m_new = MenuResource.parse(new_e.data)
                    differences.append(
                        ResourceDifference(
                            resource_type="MENU",
                            resource_name=str(name),
                            item_id=str(name),
                            item_label=f"Menu_{name}",
                            change_type="ADDED",
                            details_after=m_new.to_dict(),
                        )
                    )
                except Exception:
                    pass
                continue

            if new_e is None and old_e is not None:
                try:
                    m_old = MenuResource.parse(old_e.data)
                    differences.append(
                        ResourceDifference(
                            resource_type="MENU",
                            resource_name=str(name),
                            item_id=str(name),
                            item_label=f"Menu_{name}",
                            change_type="REMOVED",
                            details_before=m_old.to_dict(),
                        )
                    )
                except Exception:
                    pass
                continue

            if old_e is not None and new_e is not None and old_e.data != new_e.data:
                try:
                    m_old = MenuResource.parse(old_e.data)
                    m_new = MenuResource.parse(new_e.data)
                except Exception:
                    continue

                def _flatten(items: list[Any], prefix: str = "") -> dict[Any, dict[str, Any]]:
                    res: dict[Any, dict[str, Any]] = {}
                    for it in items:
                        path = f"{prefix}/{it.text}" if prefix else it.text
                        key = it.item_id if (it.item_id != 0 or not it.children) else f"item_{path}"
                        res[key] = {"id": it.item_id, "text": it.text, "flags": it.flags, "path": path}
                        if it.children:
                            res.update(_flatten(it.children, path))
                    return res

                old_items = _flatten(m_old.items)
                new_items = _flatten(m_new.items)

                for k in sorted(set(old_items) | set(new_items), key=str):
                    oi = old_items.get(k)
                    ni = new_items.get(k)
                    if oi is None and ni is not None:
                        differences.append(
                            ResourceDifference(
                                resource_type="MENU_ITEM",
                                resource_name=str(name),
                                item_id=ni["id"],
                                item_label=f"'{ni['text']}' ({ni['path']})",
                                change_type="ADDED",
                                details_after=ni,
                            )
                        )
                    elif ni is None and oi is not None:
                        differences.append(
                            ResourceDifference(
                                resource_type="MENU_ITEM",
                                resource_name=str(name),
                                item_id=oi["id"],
                                item_label=f"'{oi['text']}' ({oi['path']})",
                                change_type="REMOVED",
                                details_before=oi,
                            )
                        )
                    elif oi is not None and ni is not None and oi != ni:
                        differences.append(
                            ResourceDifference(
                                resource_type="MENU_ITEM",
                                resource_name=str(name),
                                item_id=ni["id"],
                                item_label=f"'{oi['text']}' -> '{ni['text']}'",
                                change_type="MODIFIED",
                                details_before=oi,
                                details_after=ni,
                            )
                        )

        return differences

    @staticmethod
    def extract_string_differences(old_path: Path, new_path: Path) -> list[ResourceDifference]:
        differences: list[ResourceDifference] = []
        old_entries = {e.name: e for e in ResourceReader(old_path).entries if e.resource_type == "STRING"}
        new_entries = {e.name: e for e in ResourceReader(new_path).entries if e.resource_type == "STRING"}

        for name in sorted(set(old_entries) | set(new_entries), key=str):
            old_e = old_entries.get(name)
            new_e = new_entries.get(name)
            if old_e is None or new_e is None or old_e.data == new_e.data:
                continue

            try:
                name_int = int(name) if str(name).isdigit() else 1
                b_old = StringTableBlock.from_bytes(name_int, old_e.data)
                b_new = StringTableBlock.from_bytes(name_int, new_e.data)
                for i in range(16):
                    sid = b_old.first_string_id + i
                    s_old = b_old.strings[i] if i < len(b_old.strings) else ""
                    s_new = b_new.strings[i] if i < len(b_new.strings) else ""
                    if s_old != s_new:
                        differences.append(
                            ResourceDifference(
                                resource_type="STRING",
                                resource_name=str(name),
                                item_id=sid,
                                item_label=f"String {sid}: '{s_old}' -> '{s_new}'",
                                change_type="MODIFIED" if (s_old and s_new) else ("ADDED" if s_new else "REMOVED"),
                                details_before={"id": sid, "text": s_old},
                                details_after={"id": sid, "text": s_new},
                            )
                        )
            except Exception:
                pass

        return differences


class CausalCorrelator:
    """Correlates UI and resource modifications with equivalent code changes to explain WHY resources changed."""

    @staticmethod
    def correlate(
        resource_diffs: list[ResourceDifference],
        function_matches: list[FunctionMatch],
    ) -> list[CausalCorrelation]:
        correlations: list[CausalCorrelation] = []

        # Build fast lookup maps for matched functions
        old_to_match: dict[int, FunctionMatch] = {}
        new_to_match: dict[int, FunctionMatch] = {}
        for fm in function_matches:
            if fm.old_function:
                old_to_match[fm.old_function.rva] = fm
            if fm.new_function:
                new_to_match[fm.new_function.rva] = fm

        for diff in resource_diffs:
            item_id = diff.item_id
            target_str = f"{diff.resource_type} [{diff.resource_name}] -> ID {diff.item_id} ({diff.item_label})"

            # Try to match numeric IDs (Dialog control ID, Menu item ID, String ID)
            numeric_id: int | None = None
            if isinstance(item_id, int):
                numeric_id = item_id
            elif isinstance(item_id, str) and item_id.isdigit():
                numeric_id = int(item_id)

            if numeric_id is None:
                continue

            # 1. Search for functions in Old PE referencing this numeric ID
            old_referencing_matches: list[FunctionMatch] = []
            for fm in function_matches:
                if fm.old_function and numeric_id in fm.old_function.immediates:
                    old_referencing_matches.append(fm)

            # 2. Search for functions in New PE referencing this numeric ID
            new_referencing_matches: list[FunctionMatch] = []
            for fm in function_matches:
                if fm.new_function and numeric_id in fm.new_function.immediates:
                    new_referencing_matches.append(fm)

            # Analyze Causal Connection
            if diff.change_type == "REMOVED":
                if old_referencing_matches:
                    primary = old_referencing_matches[0]
                    f_old = primary.old_function
                    f_new = primary.new_function
                    if f_new is not None:
                        api_diff = f" Eliminated APIs: {list(primary.api_calls_removed)}." if primary.api_calls_removed else ""
                        expl = (
                            f"Control/Item ID {numeric_id} was removed from the resource template. "
                            f"Equivalent handler function '{f_old.name}' (shifted from RVA {hex(f_old.rva)} to {hex(f_new.rva)}) "
                            f"deleted the WM_COMMAND/WM_NOTIFY dispatch branch for ID {numeric_id}.{api_diff}"
                        )
                        correlations.append(
                            CausalCorrelation(
                                target=target_str,
                                change_type="CONTROL_OR_ITEM_REMOVED",
                                resource_change=f"Removed item '{diff.item_label}' (ID {numeric_id})",
                                code_explanation=expl,
                                related_old_rva=hex(f_old.rva),
                                related_new_rva=hex(f_new.rva),
                                related_function_name=f_old.name,
                                confidence="HIGH",
                            )
                        )
                    else:
                        expl = (
                            f"Control/Item ID {numeric_id} was removed. "
                            f"The corresponding handler function '{f_old.name}' at RVA {hex(f_old.rva)} was deleted entirely."
                        )
                        correlations.append(
                            CausalCorrelation(
                                target=target_str,
                                change_type="HANDLER_FUNCTION_DELETED",
                                resource_change=f"Removed item '{diff.item_label}' (ID {numeric_id})",
                                code_explanation=expl,
                                related_old_rva=hex(f_old.rva),
                                related_new_rva=None,
                                related_function_name=f_old.name,
                                confidence="HIGH",
                            )
                        )
                else:
                    correlations.append(
                        CausalCorrelation(
                            target=target_str,
                            change_type="STATIC_ITEM_REMOVED",
                            resource_change=f"Removed item '{diff.item_label}' (ID {numeric_id})",
                            code_explanation="Static UI label or non-interactive item removed; no direct code-behind branch was bound to this ID in the previous binary.",
                            related_old_rva=None,
                            related_new_rva=None,
                            related_function_name=None,
                            confidence="MEDIUM",
                        )
                    )

            elif diff.change_type == "ADDED":
                if new_referencing_matches:
                    primary = new_referencing_matches[0]
                    f_new = primary.new_function
                    f_old = primary.old_function
                    api_add = f" New APIs invoked: {list(primary.api_calls_added)}." if primary.api_calls_added else ""
                    if f_old is not None:
                        expl = (
                            f"Control/Item ID {numeric_id} was added to the resource template. "
                            f"Equivalent handler function '{f_new.name}' (at RVA {hex(f_new.rva)}, previously {hex(f_old.rva)}) "
                            f"introduced a new dispatch branch handling ID {numeric_id}.{api_add}"
                        )
                        correlations.append(
                            CausalCorrelation(
                                target=target_str,
                                change_type="CONTROL_OR_ITEM_ADDED",
                                resource_change=f"Added item '{diff.item_label}' (ID {numeric_id})",
                                code_explanation=expl,
                                related_old_rva=hex(f_old.rva),
                                related_new_rva=hex(f_new.rva),
                                related_function_name=f_new.name,
                                confidence="HIGH",
                            )
                        )
                    else:
                        expl = (
                            f"Control/Item ID {numeric_id} was added. "
                            f"A new function '{f_new.name}' at RVA {hex(f_new.rva)} was created to handle this command.{api_add}"
                        )
                        correlations.append(
                            CausalCorrelation(
                                target=target_str,
                                change_type="NEW_HANDLER_CREATED",
                                resource_change=f"Added item '{diff.item_label}' (ID {numeric_id})",
                                code_explanation=expl,
                                related_old_rva=None,
                                related_new_rva=hex(f_new.rva),
                                related_function_name=f_new.name,
                                confidence="HIGH",
                            )
                        )
                else:
                    correlations.append(
                        CausalCorrelation(
                            target=target_str,
                            change_type="STATIC_ITEM_ADDED",
                            resource_change=f"Added item '{diff.item_label}' (ID {numeric_id})",
                            code_explanation="Added static UI decorative element or placeholder; not referenced directly by executable code in the new binary.",
                            related_old_rva=None,
                            related_new_rva=None,
                            related_function_name=None,
                            confidence="MEDIUM",
                        )
                    )

            elif diff.change_type == "MODIFIED":
                matched_func = old_referencing_matches[0] if old_referencing_matches else (new_referencing_matches[0] if new_referencing_matches else None)
                if matched_func and matched_func.new_function:
                    f_new = matched_func.new_function
                    f_old = matched_func.old_function
                    old_rva_str = hex(f_old.rva) if f_old else None
                    expl = (
                        f"Item ID {numeric_id} properties were modified in resource template ({diff.item_label}). "
                        f"The equivalent handler function '{f_new.name}' at RVA {hex(f_new.rva)} updated its internal response logic."
                    )
                    correlations.append(
                        CausalCorrelation(
                            target=target_str,
                            change_type="ITEM_MODIFIED",
                            resource_change=f"Modified item '{diff.item_label}' (ID {numeric_id})",
                            code_explanation=expl,
                            related_old_rva=old_rva_str,
                            related_new_rva=hex(f_new.rva),
                            related_function_name=f_new.name,
                            confidence="HIGH",
                        )
                    )

        return correlations


def compare_pe_behavior(
    old_pe_path: str | Path,
    new_pe_path: str | Path,
    decompiled_old: dict[str | int, str] | None = None,
    decompiled_new: dict[str | int, str] | None = None,
) -> BehavioralDiffReport:
    """Executes the full behavioral diffing pipeline between two versions of a Windows PE binary."""
    old_path = Path(old_pe_path).expanduser().resolve()
    new_path = Path(new_pe_path).expanduser().resolve()

    if not old_path.is_file():
        raise FileNotFoundError(f"Old PE file not found: {old_path}")
    if not new_path.is_file():
        raise FileNotFoundError(f"New PE file not found: {new_path}")

    old_bytes = old_path.read_bytes()
    new_bytes = new_path.read_bytes()
    files_identical = old_bytes == new_bytes

    # 1. Extract functions from both binaries
    old_ext = FunctionExtractor(old_path)
    new_ext = FunctionExtractor(new_path)

    old_funcs = old_ext.extract_all_functions(decompiled_map=decompiled_old)
    new_funcs = new_ext.extract_all_functions(decompiled_map=decompiled_new)

    # 2. Match equivalent functions
    matcher = FunctionMatcher()
    matched_funcs = matcher.match_functions(old_funcs, new_funcs)

    # 3. Compare fine-grained resources (Dialogs, Menus, Strings)
    dialog_diffs = ResourceComparator.extract_dialog_differences(old_path, new_path)
    menu_diffs = ResourceComparator.extract_menu_differences(old_path, new_path)
    string_diffs = ResourceComparator.extract_string_differences(old_path, new_path)
    all_resource_diffs = dialog_diffs + menu_diffs + string_diffs

    # 4. Generate Causal Correlations (Linking UI differences to Code differences)
    causal_correlations = CausalCorrelator.correlate(all_resource_diffs, matched_funcs)

    # 5. Synthesize Human Summary (Arabic and English)
    human_summary: list[str] = [
        "=== تقرير مقارنة الإصدارات على مستوى السلوك (Behavioral Version Diff) ===",
        f"الملف القديم: {old_path.name} | الملف الجديد: {new_path.name}",
        "",
        "1. ما الذي تغيّر في الموارد وعناصر الواجهة؟ (What Changed in UI & Resources):",
    ]

    if not all_resource_diffs:
        human_summary.append("   - لم تطرأ أي تغييرات هيكلية على الحوارات أو القوائم أو السلاسل النصية.")
    else:
        for r_diff in all_resource_diffs[:15]:
            status_ar = "إضافة" if r_diff.change_type == "ADDED" else ("حذف" if r_diff.change_type == "REMOVED" else "تعديل")
            human_summary.append(f"   - [{status_ar}] {r_diff.resource_type} '{r_diff.resource_name}': {r_diff.item_label} (معرف {r_diff.item_id})")
        if len(all_resource_diffs) > 15:
            human_summary.append(f"   - ... و {len(all_resource_diffs) - 15} تغييرات إضافية في الموارد.")

    human_summary.append("")
    human_summary.append("2. ما التغيير البرمجي الذي يفسر اختلاف المورد؟ (What Code Change Explains the Difference):")

    if not causal_correlations:
        human_summary.append("   - لا توجد تغييرات برمجية مباشرة تفسر اختلاف الموارد (الموارد متطابقة أو عناصر رسومية ثابتة).")
    else:
        for c_corr in causal_correlations[:15]:
            human_summary.append(f"   * [{c_corr.change_type}] {c_corr.target}:")
            human_summary.append(f"     <- {c_corr.code_explanation}")
        if len(causal_correlations) > 15:
            human_summary.append(f"   * ... و {len(causal_correlations) - 15} ارتباطات سببية إضافية.")

    summary_stats = {
        "filesIdentical": files_identical,
        "oldFunctionCount": len(old_funcs),
        "newFunctionCount": len(new_funcs),
        "matchedCount": sum(1 for m in matched_funcs if m.status in ("IDENTICAL", "RELOCATED_ONLY", "EQUIVALENT_MODIFIED")),
        "relocatedCount": sum(1 for m in matched_funcs if m.status == "RELOCATED_ONLY"),
        "modifiedLogicCount": sum(1 for m in matched_funcs if m.status == "EQUIVALENT_MODIFIED"),
        "addedFunctionsCount": sum(1 for m in matched_funcs if m.status == "ADDED"),
        "removedFunctionsCount": sum(1 for m in matched_funcs if m.status == "REMOVED"),
        "resourceDifferencesCount": len(all_resource_diffs),
        "causalCorrelationsCount": len(causal_correlations),
    }

    return BehavioralDiffReport(
        old_path=str(old_path),
        new_path=str(new_path),
        files_identical=files_identical,
        summary=summary_stats,
        function_matches=tuple(matched_funcs),
        resource_differences=tuple(all_resource_diffs),
        causal_correlations=tuple(causal_correlations),
        human_summary=tuple(human_summary),
    )

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief

from .parse_cache import shared_parse
from .pe_metadata import PEMetadataInspector
from .signature import inspect_signature


@dataclass(frozen=True)
class PEIdentity:
    schema: str
    path: str
    format: str
    machine: str
    kind: str
    subsystem: str
    managed: bool
    satellite: dict[str, Any]
    signed: bool
    overlay_bytes: int
    packer_hint: dict[str, str] | None
    notices: tuple[dict[str, str], ...]
    pdb_path: str | None = None
    managed_metadata: dict[str, Any] | None = None
    toolchain: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "path": self.path,
            "format": self.format,
            "machine": self.machine,
            "kind": self.kind,
            "subsystem": self.subsystem,
            "managed": self.managed,
            "satellite": dict(self.satellite),
            "signed": self.signed,
            "overlayBytes": self.overlay_bytes,
            "packerHint": dict(self.packer_hint) if self.packer_hint else None,
            "notices": [dict(n) for n in self.notices],
            "pdbPath": self.pdb_path,
            "managedMetadata": dict(self.managed_metadata) if self.managed_metadata else None,
            "toolchain": dict(self.toolchain) if self.toolchain else None,
        }


def _detect_overlay_bytes(binary: lief.PE.Binary, data: bytes) -> int:
    file_size = len(data)
    sec_end = max([s.pointerto_raw_data + s.sizeof_raw_data for s in binary.sections if s.sizeof_raw_data] or [0])
    sym_end = 0
    sym_ptr = binary.header.pointerto_symbol_table
    nsym = binary.header.numberof_symbols
    if sym_ptr and nsym and sym_ptr < file_size:
        strtab = sym_ptr + nsym * 18
        if strtab + 4 <= file_size:
            strsize = struct.unpack_from("<I", data, strtab)[0]
            if strtab + max(strsize, 4) <= file_size:
                sym_end = strtab + max(strsize, 4)
            else:
                sym_end = strtab
        elif strtab <= file_size:
            sym_end = strtab
    cert = binary.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
    cert_end = 0
    if cert and cert.size and cert.rva < file_size:
        cert_end = min(file_size, cert.rva + cert.size)
    pe_end = max(sec_end, sym_end, cert_end)
    return max(0, file_size - pe_end)


def classify(path: Path, *, binary: lief.PE.Binary | None = None) -> PEIdentity:
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"file not found: {path}")

    b = binary if binary is not None else shared_parse(path)
    if b is None or not isinstance(b, lief.PE.Binary):
        raise ValueError("input is not a supported PE binary")

    data = path.read_bytes()
    meta = PEMetadataInspector.inspect(path)
    sig_report = inspect_signature(path, binary=b)

    # Format: PE32 or PE32+
    magic = b.optional_header.magic
    fmt = "PE32+" if magic == lief.PE.PE_TYPE.PE32_PLUS else "PE32"

    # Machine
    machine_raw = str(b.header.machine).split(".")[-1]
    machine_map = {
        "AMD64": "x64",
        "I386": "x86",
        "ARM64": "ARM64",
        "ARM": "ARM",
    }
    machine = machine_map.get(machine_raw, machine_raw)

    # Subsystem
    sub_raw = str(b.optional_header.subsystem).split(".")[-1]
    if "WINDOWS_GUI" in sub_raw:
        subsystem = "windows-gui"
    elif "WINDOWS_CUI" in sub_raw:
        subsystem = "console"
    elif "NATIVE" in sub_raw:
        subsystem = "native"
    elif "EFI" in sub_raw:
        subsystem = "efi"
    else:
        subsystem = "unknown"

    # Kind: exe | dll | driver | resource-only
    is_dll = b.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
    has_exec_section = any(s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE) for s in b.sections)
    entrypoint = b.optional_header.addressof_entrypoint

    if is_dll and (entrypoint == 0 or not has_exec_section) and any(s.name == ".rsrc" for s in b.sections):
        kind = "resource-only"
    elif subsystem == "native":
        kind = "driver"
    elif is_dll:
        kind = "dll"
    else:
        kind = "exe"

    # Packer hint (only well-known factual section names)
    packer_hint = None
    section_names = [s.name for s in b.sections]
    if any(n in ("UPX0", "UPX1", "UPX2") for n in section_names):
        packer_hint = {"name": "UPX", "basis": "section names UPX0/UPX1"}

    overlay_bytes = _detect_overlay_bytes(b, data)

    pdb_path: str | None = None
    if getattr(b, "has_debug", False):
        try:
            for dbg in b.debug:
                if hasattr(dbg, "filename") and dbg.filename:
                    pdb_path = str(dbg.filename)
                    break
        except Exception:
            pass

    # Notices
    notices: list[dict[str, str]] = []
    if sig_report.present:
        notices.append({
            "code": "SIGNATURE_WILL_BREAK",
            "level": "warning",
            "message": "This PE is digitally signed. Editing resources will invalidate the Authenticode signature.",
        })
    if meta.is_dotnet:
        notices.append({
            "code": "MANAGED_RESOURCES_NOT_EDITABLE",
            "level": "info",
            "message": "Managed .NET assembly detected. Only Win32 .rsrc resources are modified.",
        })
    if packer_hint:
        notices.append({
            "code": "PACKER_HINT",
            "level": "warning",
            "message": f"Packed binary ({packer_hint['name']}) detected. Some resources may be compressed or unreachable.",
        })
    if overlay_bytes > 0:
        notices.append({
            "code": "OVERLAY_PRESENT",
            "level": "info",
            "message": f"PE contains {overlay_bytes} bytes of trailing overlay data outside standard PE sections.",
        })
    if pdb_path:
        notices.append({
            "code": "PDB_PATH_LEAK",
            "level": "info",
            "message": f"PDB Debug Path exposed: {pdb_path}",
        })
    if meta.is_mui_base:
        notices.append({
            "code": "MUI_BASE_EXECUTABLE",
            "level": "info",
            "message": f"Windows MUI base executable detected with {len(meta.companion_mui_files)} companion MUI resource files.",
        })
    if meta.toolchain:
        tt = meta.toolchain.get("toolchainType")
        if tt == "GO":
            go = meta.toolchain.get("go") or {}
            ver = go.get("version") or "Go"
            cnt = go.get("dependencyCount", 0)
            notices.append({
                "code": "TOOLCHAIN_GO",
                "level": "info",
                "message": f"Compiled Go binary detected ({ver}, {cnt} dependencies).",
            })
        elif tt == "RUST":
            rust = meta.toolchain.get("rust") or {}
            commit = rust.get("rustcCommit") or "unknown"
            cnt = rust.get("dependencyCount", 0)
            notices.append({
                "code": "TOOLCHAIN_RUST",
                "level": "info",
                "message": f"Compiled Rust binary detected (rustc commit {commit[:10] if commit else 'unknown'}, {cnt} dependencies).",
            })
    if meta.managed_metadata:
        clr = meta.managed_metadata.get("metadataVersion") or meta.managed_metadata.get("runtimeVersion") or "CLR"
        rcnt = meta.managed_metadata.get("resourceCount", 0)
        scnt = meta.managed_metadata.get("userStringCount", 0)
        notices.append({
            "code": "MANAGED_METADATA_DISCOVERED",
            "level": "info",
            "message": f".NET CLI Metadata: {clr} ({rcnt} manifest resources, {scnt} user strings).",
        })

    satellite = {
        "mui": meta.is_mui,
        "hasMuiResource": meta.has_mui_resource,
        "isMuiBase": meta.is_mui_base,
        "companionMuiFiles": list(meta.companion_mui_files),
        "baseExecutable": meta.base_executable,
        "resourcesDll": path.name.lower().endswith(".resources.dll"),
        "languageHint": meta.language_hint,
    }

    return PEIdentity(
        schema="resource_studio.pe_identity.v1",
        path=str(path),
        format=fmt,
        machine=machine,
        kind=kind,
        subsystem=subsystem,
        managed=meta.is_dotnet,
        satellite=satellite,
        signed=sig_report.present,
        overlay_bytes=overlay_bytes,
        packer_hint=packer_hint,
        notices=tuple(notices),
        pdb_path=pdb_path,
        managed_metadata=dict(meta.managed_metadata) if meta.managed_metadata else None,
        toolchain=dict(meta.toolchain) if meta.toolchain else None,
    )

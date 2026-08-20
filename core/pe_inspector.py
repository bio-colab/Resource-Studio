from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import lief


@dataclass(frozen=True)
class PEInspectorReport:
    path: str
    sha256: str
    size: int
    machine: str
    entrypoint: int
    imagebase: int
    checksum: int
    computed_checksum: int
    checksum_valid: bool
    sections: tuple[dict[str, Any], ...]
    imports: tuple[dict[str, Any], ...]
    exports: tuple[dict[str, Any], ...]
    relocations: tuple[dict[str, Any], ...]
    tls: dict[str, Any] | None
    debug: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "machine": self.machine,
            "entrypoint": self.entrypoint,
            "imagebase": self.imagebase,
            "checksum": self.checksum,
            "computedChecksum": self.computed_checksum,
            "checksumValid": self.checksum_valid,
            "sections": [dict(item) for item in self.sections],
            "imports": [dict(item) for item in self.imports],
            "exports": [dict(item) for item in self.exports],
            "relocations": [dict(item) for item in self.relocations],
            "tls": dict(self.tls) if self.tls else None,
            "debug": [dict(item) for item in self.debug],
            "warnings": list(self.warnings),
        }


class PEInspector:
    @staticmethod
    def inspect(path: Path) -> PEInspectorReport:
        path = Path(path).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"file not found: {path}")
        data = path.read_bytes()
        try:
            binary = lief.parse(str(path))
        except Exception as exc:
            raise ValueError(f"cannot parse PE: {exc}") from exc
        if binary is None or not isinstance(binary, lief.PE.Binary):
            raise ValueError("input is not a supported PE binary")
        warnings: list[str] = []
        exports = tuple(_export_record(item) for item in _iter_or_empty(getattr(binary, "exported_functions", [])))
        if getattr(binary, "has_exports", False) and not exports:
            warnings.append("PE declares an export directory but no exported functions were exposed by LIEF")
        tls = _tls_record(getattr(binary, "tls", None))
        if getattr(binary, "has_tls", False) and tls is None:
            warnings.append("PE declares TLS but LIEF did not expose TLS details")
        return PEInspectorReport(
            path=str(path),
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            machine=str(binary.header.machine),
            entrypoint=int(binary.optional_header.addressof_entrypoint),
            imagebase=int(binary.optional_header.imagebase),
            checksum=int(binary.optional_header.checksum),
            computed_checksum=int(binary.compute_checksum()),
            checksum_valid=bool(binary.optional_header.checksum and binary.optional_header.checksum == binary.compute_checksum()),
            sections=tuple(_section_record(section) for section in _iter_or_empty(binary.sections)),
            imports=tuple(_import_record(library) for library in _iter_or_empty(binary.imports)),
            exports=exports,
            relocations=tuple(_relocation_record(block) for block in _iter_or_empty(binary.relocations)),
            tls=tls,
            debug=tuple(_debug_record(item) for item in _iter_or_empty(binary.debug)),
            warnings=tuple(warnings),
        )


def _section_record(section: Any) -> dict[str, Any]:
    return {
        "name": str(_safe(section, "name", "")),
        "virtualAddress": int(_safe(section, "virtual_address", 0)),
        "virtualSize": int(_safe(section, "virtual_size", 0)),
        "rawOffset": int(_safe(section, "pointerto_raw_data", 0)),
        "rawSize": int(_safe(section, "sizeof_raw_data", 0)),
        "characteristics": int(_safe(section, "characteristics", 0)),
        "entropy": float(_safe(section, "entropy", 0.0)),
    }


def _import_record(library: Any) -> dict[str, Any]:
    entries = []
    for entry in _iter_or_empty(_safe(library, "entries", [])):
        entries.append(
            {
                "name": str(_safe(entry, "name", "")),
                "ordinal": int(_safe(entry, "ordinal", 0)),
                "iatAddress": int(_safe(entry, "iat_address", 0)),
                "isOrdinal": bool(_safe(entry, "is_ordinal", False)),
            }
        )
    return {"name": str(_safe(library, "name", "")), "entries": entries}


def _export_record(symbol: Any) -> dict[str, Any]:
    return {
        "name": str(_safe(symbol, "name", "")),
        "address": int(_safe(symbol, "address", 0)),
        "ordinal": int(_safe(symbol, "ordinal", 0)),
        "isForwarder": bool(_safe(symbol, "is_forwarder", False)),
    }


def _relocation_record(block: Any) -> dict[str, Any]:
    entries = []
    for entry in _iter_or_empty(_safe(block, "entries", [])):
        entries.append(
            {
                "address": int(_safe(entry, "address", 0)),
                "data": int(_safe(entry, "data", 0)),
                "position": int(_safe(entry, "position", 0)),
                "size": int(_safe(entry, "size", 0)),
                "type": str(_safe(entry, "type", "")),
            }
        )
    return {
        "virtualAddress": int(_safe(block, "virtual_address", 0)),
        "blockSize": int(_safe(block, "block_size", 0)),
        "entries": entries,
    }


def _tls_record(tls: Any) -> dict[str, Any] | None:
    if tls is None:
        return None
    return {
        "addressofCallbacks": int(_safe(tls, "addressof_callbacks", 0)),
        "addressofIndex": int(_safe(tls, "addressof_index", 0)),
        "addressofRawData": int(_safe(tls, "addressof_raw_data", 0)),
        "sizeofZeroFill": int(_safe(tls, "sizeof_zero_fill", 0)),
        "characteristics": int(_safe(tls, "characteristics", 0)),
    }


def _debug_record(item: Any) -> dict[str, Any]:
    return {
        "type": str(_safe(item, "type", "")),
        "timestamp": int(_safe(item, "timestamp", 0)),
        "pointerToRawData": int(_safe(item, "pointerto_rawdata", 0)),
        "size": int(_safe(item, "sizeof_data", 0)),
        "filename": str(_safe(item, "filename", "")),
        "guid": str(_safe(item, "guid", "")),
        "age": int(_safe(item, "age", 0)),
    }


def _safe(value: Any, attribute: str, default: Any) -> Any:
    try:
        result = getattr(value, attribute)
        return default if result is None else result
    except Exception:
        return default


def _iter_or_empty(value: Iterable[Any] | None) -> Iterable[Any]:
    return () if value is None else value

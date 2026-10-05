from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


class RawResourceParserError(ValueError):
    pass


_TYPE_NAMES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATORS",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    24: "MANIFEST",
}


@dataclass(frozen=True)
class RawResourceLeaf:
    resource_type: str
    name: str
    language: int
    rva: int
    size: int
    offset: int
    code_page: int
    sha256: str

    @property
    def key(self) -> tuple[str, str, int]:
        return self.resource_type, self.name, self.language

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "name": self.name,
            "language": self.language,
            "rva": self.rva,
            "size": self.size,
            "offset": self.offset,
            "codePage": self.code_page,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class RawResourceReport:
    path: str
    resource_rva: int
    resource_size: int
    leaves: tuple[RawResourceLeaf, ...]
    issues: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "resourceRva": self.resource_rva,
            "resourceSize": self.resource_size,
            "leafCount": len(self.leaves),
            "leaves": [leaf.to_dict() for leaf in self.leaves],
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class RawResourceComparison:
    matches: bool
    missing: tuple[tuple[str, str, int], ...]
    extra: tuple[tuple[str, str, int], ...]
    changed: tuple[tuple[str, str, int], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "matches": self.matches,
            "missing": [list(item) for item in self.missing],
            "extra": [list(item) for item in self.extra],
            "changed": [list(item) for item in self.changed],
        }


def parse_raw_resources(path: Path) -> RawResourceReport:
    path = Path(path).expanduser().resolve()
    data = path.read_bytes()
    pe_offset, sections, resource_rva, resource_size = _headers(data)
    if not resource_rva or not resource_size:
        return RawResourceReport(str(path), resource_rva, resource_size, ())
    base = _rva_to_offset(resource_rva, sections, len(data))
    if base is None:
        raise RawResourceParserError("resource directory RVA is outside section bounds")
    limit = min(len(data), base + resource_size)
    leaves: list[RawResourceLeaf] = []
    issues: list[str] = []
    visited: set[int] = set()
    _walk_directory(data, base, limit, base, (), leaves, issues, visited, 0)
    leaves.sort(key=lambda leaf: leaf.key)
    return RawResourceReport(str(path), resource_rva, resource_size, tuple(leaves), tuple(dict.fromkeys(issues)))


def compare_with_graph(report: RawResourceReport, graph: Mapping[str, Any]) -> RawResourceComparison:
    raw = {leaf.key: leaf.sha256 for leaf in report.leaves}
    graph_leaves = graph.get("leaves", [])
    expected = {
        (str(leaf.get("type")), str(leaf.get("name")), int(leaf.get("language", 0))): str(leaf.get("sha256"))
        for leaf in graph_leaves
    }
    missing = tuple(sorted(expected.keys() - raw.keys()))
    extra = tuple(sorted(raw.keys() - expected.keys()))
    changed = tuple(sorted(key for key in expected.keys() & raw.keys() if expected[key] != raw[key]))
    return RawResourceComparison(not missing and not extra and not changed and not report.issues, missing, extra, changed)


def _headers(data: bytes) -> tuple[int, list[tuple[int, int, int, int, str]], int, int]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise RawResourceParserError("missing DOS header")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise RawResourceParserError("missing PE signature")
    number_sections = _u16(data, pe_offset + 6)
    size_optional = _u16(data, pe_offset + 20)
    optional = pe_offset + 24
    if optional + size_optional > len(data) or size_optional < 96:
        raise RawResourceParserError("invalid optional header bounds")
    magic = _u16(data, optional)
    if magic == 0x10B:
        directory_count_offset = optional + 92
        directory_offset = optional + 96
    elif magic == 0x20B:
        directory_count_offset = optional + 108
        directory_offset = optional + 112
    else:
        raise RawResourceParserError(f"unsupported optional header magic: {magic:#x}")
    directory_count = _u32(data, directory_count_offset) if directory_count_offset + 4 <= optional + size_optional else 0
    if directory_count <= 2 and directory_offset + 24 <= optional + size_optional:
        resource_rva, resource_size = 0, 0
    else:
        resource_rva = _u32(data, directory_offset + 16)
        resource_size = _u32(data, directory_offset + 20)
    table = optional + size_optional
    sections: list[tuple[int, int, int, int, str]] = []
    for index in range(number_sections):
        start = table + index * 40
        if start + 40 > len(data):
            raise RawResourceParserError("section table exceeds file bounds")
        name = data[start : start + 8].rstrip(b"\0").decode("ascii", errors="replace")
        virtual_size = _u32(data, start + 8)
        virtual_address = _u32(data, start + 12)
        raw_size = _u32(data, start + 16)
        raw_offset = _u32(data, start + 20)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_offset, raw_size, name))
    return pe_offset, sections, resource_rva, resource_size


def _walk_directory(
    data: bytes,
    base: int,
    limit: int,
    directory_offset: int,
    prefix: tuple[str, ...],
    leaves: list[RawResourceLeaf],
    issues: list[str],
    visited: set[int],
    depth: int,
) -> None:
    if depth > 3:
        issues.append("resource directory depth exceeds type/name/language model")
        return
    if directory_offset in visited:
        issues.append("resource directory loop detected")
        return
    visited.add(directory_offset)
    if directory_offset < base or directory_offset + 16 > limit:
        issues.append("resource directory header outside resource section")
        return
    named = _u16(data, directory_offset + 12)
    ids = _u16(data, directory_offset + 14)
    count = named + ids
    entries = directory_offset + 16
    if entries + count * 8 > limit:
        issues.append("resource directory entries outside resource section")
        return
    for index in range(count):
        entry = entries + index * 8
        name_value = _u32(data, entry)
        child_value = _u32(data, entry + 4)
        label = _resource_label(data, base, limit, name_value, type_level=(len(prefix) == 0))
        if child_value & 0x80000000:
            child_offset = base + (child_value & 0x7FFFFFFF)
            _walk_directory(data, base, limit, child_offset, prefix + (label,), leaves, issues, visited, depth + 1)
            continue
        data_entry = base + child_value
        if data_entry < base or data_entry + 16 > limit or len(prefix) != 2:
            issues.append("resource data entry outside expected directory")
            continue
        rva = _u32(data, data_entry)
        size = _u32(data, data_entry + 4)
        code_page = _u32(data, data_entry + 8)
        offset = _rva_to_offset(rva, _sections_from_resource(data, base), len(data))
        if offset is None or offset + size > len(data):
            issues.append(f"resource bytes outside file: {'/'.join(prefix + (label,))}")
            continue
        resource_type, name = prefix
        try:
            language = int(label)
        except ValueError:
            issues.append(f"non-numeric resource language: {label}")
            continue
        payload = data[offset : offset + size]
        leaves.append(RawResourceLeaf(resource_type, name, language, rva, size, offset, code_page, hashlib.sha256(payload).hexdigest()))


def _sections_from_resource(data: bytes, resource_base: int) -> list[tuple[int, int, int, int, str]]:
    _, sections, _, _ = _headers(data)
    return sections


def _resource_label(data: bytes, base: int, limit: int, value: int, *, type_level: bool) -> str:
    if not value & 0x80000000:
        numeric = value & 0xFFFF
        return _TYPE_NAMES.get(numeric, str(numeric)) if type_level else str(numeric)
    offset = base + (value & 0x7FFFFFFF)
    if offset + 2 > limit:
        raise RawResourceParserError("resource string header outside resource section")
    length = _u16(data, offset)
    end = offset + 2 + length * 2
    if end > limit:
        raise RawResourceParserError("resource string outside resource section")
    return data[offset + 2 : end].decode("utf-16le", errors="replace")


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int, str]], file_size: int) -> int | None:
    for virtual_address, span, raw_offset, raw_size, _name in sections:
        if virtual_address <= rva < virtual_address + span:
            offset = raw_offset + (rva - virtual_address)
            if 0 <= offset <= file_size:
                return offset
    return None


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise RawResourceParserError("truncated PE field")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise RawResourceParserError("truncated PE field")
    return struct.unpack_from("<I", data, offset)[0]

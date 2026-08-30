"""Pure PE parsing and resource-directory indexing helpers (no session state)."""
import hashlib
import struct
from typing import Any

from rs_mcp.state import MAX_RESOURCE_NODES

TYPE_NAMES = {
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
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated PE data")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("truncated PE data")
    return struct.unpack_from("<I", data, offset)[0]


def _resource_label(data: bytes, base: int, value: int) -> str | int:
    if value & 0x80000000:
        offset = base + (value & 0x7FFFFFFF)
        length = _u16(data, offset)
        end = offset + 2 + length * 2
        if end > len(data):
            raise ValueError("truncated resource name")
        return data[offset + 2 : end].decode("utf-16le", errors="replace")
    return value & 0xFFFF


def _type_label(value: str | int) -> str | int:
    if isinstance(value, int):
        return TYPE_NAMES.get(value, value)
    return value


def _parse_pe(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "is_pe": False,
        "architecture": None,
        "machine": None,
        "number_of_sections": 0,
        "resource_directory": None,
        "sections": [],
    }
    if len(data) < 64 or data[:2] != b"MZ":
        return result
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return result

    coff = pe_offset + 4
    machine = _u16(data, coff)
    section_count = _u16(data, coff + 2)
    optional_size = _u16(data, coff + 16)
    optional = coff + 20
    if optional + optional_size > len(data):
        raise ValueError("truncated optional header")
    magic = _u16(data, optional)
    if magic == 0x10B:
        architecture = "PE32"
        directory_start = optional + 96
    elif magic == 0x20B:
        architecture = "PE32+"
        directory_start = optional + 112
    else:
        raise ValueError(f"unsupported optional-header magic: 0x{magic:04x}")

    sections_start = optional + optional_size
    sections: list[dict[str, int]] = []
    for index in range(section_count):
        current = sections_start + index * 40
        if current + 40 > len(data):
            raise ValueError("truncated section table")
        name = data[current : current + 8].rstrip(b"\0").decode("ascii", errors="replace")
        sections.append(
            {
                "index": index,
                "name": name,
                "virtual_size": _u32(data, current + 8),
                "virtual_address": _u32(data, current + 12),
                "raw_size": _u32(data, current + 16),
                "raw_pointer": _u32(data, current + 20),
            }
        )

    resource_rva = 0
    resource_size = 0
    resource_entry = directory_start + 2 * 8
    if resource_entry + 8 <= optional + optional_size:
        resource_rva = _u32(data, resource_entry)
        resource_size = _u32(data, resource_entry + 4)

    result.update(
        {
            "is_pe": True,
            "architecture": architecture,
            "machine": f"0x{machine:04x}",
            "number_of_sections": section_count,
            "sections": sections,
            "resource_directory": {"rva": resource_rva, "size": resource_size},
        }
    )
    return result


def _rva_to_offset(pe: dict[str, Any], rva: int) -> int | None:
    for section in pe["sections"]:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + span:
            return section["raw_pointer"] + (rva - start)
    return None


def _resource_entries(data: bytes, pe: dict[str, Any]) -> list[dict[str, Any]]:
    directory = pe["resource_directory"]
    if not directory or not directory["rva"]:
        return []
    resource_base = _rva_to_offset(pe, directory["rva"])
    if resource_base is None or resource_base >= len(data):
        return []

    found: list[dict[str, Any]] = []
    visited: set[int] = set()
    node_count = 0

    def walk(directory_offset: int, path: list[str | int], depth: int) -> None:
        nonlocal node_count
        node_count += 1
        if node_count > MAX_RESOURCE_NODES or depth > 3:
            raise ValueError("resource directory exceeds safe traversal limits")
        if directory_offset in visited:
            return
        visited.add(directory_offset)
        if directory_offset + 16 > len(data):
            raise ValueError("truncated resource directory")
        named = _u16(data, directory_offset + 12)
        ids = _u16(data, directory_offset + 14)
        total = named + ids
        entries_offset = directory_offset + 16
        if entries_offset + total * 8 > len(data):
            raise ValueError("truncated resource entries")

        for index in range(total):
            entry = entries_offset + index * 8
            label = _resource_label(data, resource_base, _u32(data, entry))
            target = _u32(data, entry + 4)
            if target & 0x80000000:
                walk(resource_base + (target & 0x7FFFFFFF), path + [label], depth + 1)
                continue
            data_entry = resource_base + target
            if data_entry + 16 > len(data):
                raise ValueError("truncated resource data entry")
            payload_rva = _u32(data, data_entry)
            payload_size = _u32(data, data_entry + 4)
            payload_offset = _rva_to_offset(pe, payload_rva)
            if payload_offset is None or payload_offset + payload_size > len(data):
                payload_offset = None
            resource_type = _type_label(path[0]) if path else "UNKNOWN"
            resource_name = path[1] if len(path) > 1 else "UNKNOWN"
            language = path[2] if len(path) > 2 else None
            payload_hash = None
            if payload_offset is not None:
                payload_hash = _sha256(data[payload_offset : payload_offset + payload_size])
            found.append(
                {
                    "type": resource_type,
                    "name": resource_name,
                    "language": language,
                    "size": payload_size,
                    "data_rva": payload_rva,
                    "data_offset": payload_offset,
                    "sha256": payload_hash,
                }
            )

    walk(resource_base, [], 0)
    found.sort(key=lambda item: (str(item["type"]), str(item["name"]), str(item["language"])))
    return found


def _resource_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (str(item.get("type")), str(item.get("name")), str(item.get("language")))


def _resource_lookup(resources: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    return {_resource_key(item): item for item in resources}

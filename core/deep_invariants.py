from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief


@dataclass(frozen=True)
class DeepPEInvariantReport:
    path: str
    valid: bool
    headers: dict[str, Any]
    sections: tuple[dict[str, Any], ...]
    directories: tuple[dict[str, Any], ...]
    issues: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "valid": self.valid,
            "headers": dict(self.headers),
            "sections": [dict(item) for item in self.sections],
            "directories": [dict(item) for item in self.directories],
            "issues": list(self.issues),
        }


def inspect_deep(path: Path, *, binary: Any | None = None) -> DeepPEInvariantReport:
    path = Path(path).expanduser().resolve()
    binary = binary if binary is not None else lief.parse(str(path))
    if binary is None or not isinstance(binary, lief.PE.Binary):
        raise ValueError(f"not a supported PE: {path}")
    file_size = path.stat().st_size
    optional = binary.optional_header
    file_alignment = _int(optional, "file_alignment")
    section_alignment = _int(optional, "section_alignment")
    size_of_headers = _int(optional, "sizeof_headers")
    size_of_image = _int(optional, "sizeof_image")
    headers = {
        "machine": str(binary.header.machine),
        "numberOfSections": len(binary.sections),
        "timestamp": _int(binary.header, "time_date_stamp"),
        "characteristics": _int(binary.header, "characteristics"),
        "fileAlignment": file_alignment,
        "sectionAlignment": section_alignment,
        "sizeOfHeaders": size_of_headers,
        "sizeOfImage": size_of_image,
        "imagebase": _int(optional, "imagebase"),
        "entrypoint": _int(optional, "addressof_entrypoint"),
        "checksum": _int(optional, "checksum"),
    }
    issues: list[str] = []
    if size_of_headers and size_of_headers > file_size:
        issues.append("size_of_headers exceeds file size")
    if size_of_image and section_alignment and size_of_image % section_alignment:
        issues.append("size_of_image is not section-aligned")

    sections: list[dict[str, Any]] = []
    raw_ranges: list[tuple[int, int, str]] = []
    virtual_ranges: list[tuple[int, int, str]] = []
    for section in binary.sections:
        raw_offset = _int(section, "pointerto_raw_data")
        raw_size = _int(section, "sizeof_raw_data")
        virtual_address = _int(section, "virtual_address")
        virtual_size = _int(section, "virtual_size")
        raw_end = raw_offset + raw_size
        virtual_end = virtual_address + max(virtual_size, raw_size)
        name = str(section.name)
        item = {
            "name": name,
            "virtualAddress": virtual_address,
            "virtualSize": virtual_size,
            "virtualEnd": virtual_end,
            "rawOffset": raw_offset,
            "rawSize": raw_size,
            "rawEnd": raw_end,
            "characteristics": _int(section, "characteristics"),
        }
        sections.append(item)
        if raw_size:
            raw_ranges.append((raw_offset, raw_end, name))
            if raw_offset < 0 or raw_end > file_size:
                issues.append(f"section raw bounds outside file: {name}")
            if file_alignment and raw_offset and raw_offset % file_alignment:
                issues.append(f"section raw offset misaligned: {name}")
        if virtual_size or raw_size:
            virtual_ranges.append((virtual_address, virtual_end, name))
            if section_alignment and virtual_address % section_alignment:
                issues.append(f"section virtual address misaligned: {name}")

    for left, right in _overlaps(raw_ranges):
        issues.append(f"section raw ranges overlap: {left}/{right}")
    for left, right in _overlaps(virtual_ranges):
        issues.append(f"section virtual ranges overlap: {left}/{right}")

    directories: list[dict[str, Any]] = []
    for directory in binary.data_directories:
        rva = _int(directory, "rva")
        size = _int(directory, "size")
        kind = str(directory.type)
        directories.append({"type": kind, "rva": rva, "size": size, "end": rva + size})
        if size and size_of_image and rva + size > size_of_image:
            issues.append(f"data directory outside image: {kind}")

    return DeepPEInvariantReport(
        str(path),
        not issues,
        headers,
        tuple(sections),
        tuple(directories),
        tuple(dict.fromkeys(issues)),
    )


def _int(value: Any, name: str) -> int:
    try:
        return int(getattr(value, name, 0))
    except Exception:
        return 0


def _overlaps(ranges: list[tuple[int, int, str]]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    ordered = sorted(ranges)
    for index, current in enumerate(ordered):
        for other in ordered[index + 1 :]:
            if other[0] >= current[1]:
                break
            if other[1] > current[0]:
                result.append((current[2], other[2]))
    return result

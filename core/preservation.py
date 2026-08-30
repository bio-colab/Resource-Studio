from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .deep_invariants import inspect_deep
from .invariants import snapshot


@dataclass(frozen=True)
class ByteChange:
    offset: int
    length: int
    category: str
    label: str
    before_sha256: str
    after_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "length": self.length,
            "category": self.category,
            "label": self.label,
            "beforeSha256": self.before_sha256,
            "afterSha256": self.after_sha256,
        }


@dataclass(frozen=True)
class PreservationMap:
    schema: str
    before_sha256: str
    after_sha256: str
    changed_bytes: int
    changes: tuple[ByteChange, ...]
    unexpected: tuple[ByteChange, ...]

    @property
    def passed(self) -> bool:
        return not self.unexpected

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "beforeSha256": self.before_sha256,
            "afterSha256": self.after_sha256,
            "changedBytes": self.changed_bytes,
            "passed": self.passed,
            "changes": [change.to_dict() for change in self.changes],
            "unexpected": [change.to_dict() for change in self.unexpected],
        }


def build_preservation_map(
    before_path: Path,
    after_path: Path,
    *,
    resource_type: str | int,
    resource_name: str | int,
    language: int | None,
) -> PreservationMap:
    before_path = Path(before_path).expanduser().resolve()
    after_path = Path(after_path).expanduser().resolve()
    before = before_path.read_bytes()
    after = after_path.read_bytes()
    target = (str(resource_type), str(resource_name), language)
    before_ranges = _expected_ranges(before_path, target)
    after_ranges = _expected_ranges(after_path, target)
    ranges = _merge_ranges(before_ranges + after_ranges)
    changes: list[ByteChange] = []
    for offset, length in _diff_ranges(before, after):
        category, label = _classify(offset, length, ranges)
        changes.append(
            ByteChange(
                offset,
                length,
                category,
                label,
                hashlib.sha256(before[offset : offset + length]).hexdigest(),
                hashlib.sha256(after[offset : offset + length]).hexdigest(),
            )
        )
    unexpected = tuple(change for change in changes if change.category == "UNEXPECTED")
    return PreservationMap(
        schema="resource_studio.preservation_map.v1",
        before_sha256=hashlib.sha256(before).hexdigest(),
        after_sha256=hashlib.sha256(after).hexdigest(),
        changed_bytes=sum(change.length for change in changes),
        changes=tuple(changes),
        unexpected=unexpected,
    )


def _expected_ranges(path: Path, target: tuple[str, str, int | None]) -> list[tuple[int, int, str, str]]:
    data = path.read_bytes()
    result: list[tuple[int, int, str, str]] = []
    graph = snapshot(path)
    deep = inspect_deep(path)
    resource_names = {str(item["name"]) for item in graph.sections if item.get("isResource")}
    for section in deep.sections:
        name = str(section.get("name", ""))
        if name in resource_names and int(section.get("rawSize", 0)):
            result.append((int(section["rawOffset"]), int(section["rawEnd"]), "EXPECTED_RESOURCE_CONTAINER", name))
    for leaf in graph.resources:
        key = (str(leaf.get("type")), str(leaf.get("name")), leaf.get("language"))
        offset = int(leaf.get("offset", 0))
        size = int(leaf.get("size", 0))
        if size and key == target:
            result.append((offset, offset + size, "EXPECTED_TARGET_RESOURCE", f"{key[0]}:{key[1]}:{key[2]}"))
    for start, end, label in _header_ranges(data, resource_names):
        result.append((start, end, "EXPECTED_HEADER_RECALC", label))
    return result


def _header_ranges(data: bytes, resource_names: set[str]) -> tuple[tuple[int, int, str], ...]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return ()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return ()
    number_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    size_optional = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    if optional + size_optional > len(data) or size_optional < 68:
        return ()
    ranges: list[tuple[int, int, str]] = [
        (pe_offset + 6, pe_offset + 8, "NumberOfSections"),
        (optional + 56, optional + 60, "SizeOfImage"),
        (optional + 64, optional + 68, "CheckSum"),
    ]
    magic = struct.unpack_from("<H", data, optional)[0]
    directory_base = optional + (112 if magic == 0x20B else 96)
    if directory_base + 24 <= optional + size_optional:
        ranges.append((directory_base + 16, directory_base + 24, "ResourceDirectory"))
    table = optional + size_optional
    for index in range(number_sections):
        start = table + index * 40
        if start + 40 > len(data):
            break
        name = data[start : start + 8].rstrip(b"\0").decode("ascii", errors="replace")
        if name in resource_names:
            ranges.append((start, start + 40, f"{name} section header"))
    return tuple(ranges)


def _diff_ranges(before: bytes, after: bytes) -> Iterable[tuple[int, int]]:
    """Contiguous byte ranges where ``after`` differs from ``before``.

    64 KiB chunks are compared at C speed first, so the per-byte walk only
    runs inside unequal chunks; cost tracks the changed area instead of the
    whole file (~×700 faster on a 64 MB image with scattered changes).

    Semantics: bytes beyond the common length count as changed, and a
    changed range reaching end-of-file IS emitted. The previous
    implementation silently dropped the final open range, so appended or
    truncated tails never appeared in the preservation map
    (tests/core/test_diff_ranges_regression.py pins this).
    """
    limit = max(len(before), len(after))
    common = min(len(before), len(after))
    start: int | None = None
    chunk = 65536
    base = 0
    while base < common:
        stop = min(base + chunk, common)
        if before[base:stop] == after[base:stop]:
            if start is not None:
                yield start, base - start
                start = None
        else:
            for offset in range(base, stop):
                if before[offset] != after[offset]:
                    if start is None:
                        start = offset
                elif start is not None:
                    yield start, offset - start
                    start = None
        base = stop
    if start is None and common < limit:
        start = common
    if start is not None:
        yield start, limit - start


def _merge_ranges(ranges: Iterable[tuple[int, int, str, str]]) -> tuple[tuple[int, int, str, str], ...]:
    return tuple(sorted(ranges, key=lambda item: (item[0], item[1], item[2])))


def _classify(offset: int, length: int, ranges: Iterable[tuple[int, int, str, str]]) -> tuple[str, str]:
    end = offset + length
    matches = [(category, label) for start, stop, category, label in ranges if offset >= start and end <= stop]
    if not matches:
        return "UNEXPECTED", "outside expected ranges"
    for category in ("EXPECTED_TARGET_RESOURCE", "EXPECTED_HEADER_RECALC", "EXPECTED_RESOURCE_CONTAINER"):
        for match_category, label in matches:
            if match_category == category:
                return match_category, label
    return matches[0]

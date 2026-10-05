from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Any

from .project import ResourceEntry


@dataclass(frozen=True)
class SearchHit:
    resource_type: str
    name: str
    language: int | None
    field: str
    offset: int | None
    preview: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "name": self.name,
            "language": self.language,
            "field": self.field,
            "offset": self.offset,
            "preview": self.preview,
        }


def search_resources(
    entries: Iterable[ResourceEntry],
    query: str,
    *,
    regex: bool = False,
    case_sensitive: bool = False,
    hex_query: bool = False,
) -> list[SearchHit]:
    if not query:
        raise ValueError("search query cannot be empty")
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(query, flags) if regex and not hex_query else None
    needle = bytes.fromhex(query.replace(" ", "")) if hex_query else None
    hits: list[SearchHit] = []
    for entry in entries:
        metadata = f"{entry.resource_type} {entry.name} {entry.language if entry.language is not None else ''}"
        if _matches(metadata, query, pattern, case_sensitive):
            hits.append(SearchHit(entry.resource_type, entry.name, entry.language, "metadata", _offset(entry), metadata))
        if needle is not None:
            offset = entry.data.find(needle)
            if offset >= 0:
                hits.append(SearchHit(entry.resource_type, entry.name, entry.language, "bytes", _offset(entry, offset), entry.data[offset:offset + min(len(needle), 32)].hex(" ")))
            continue
        text = entry.data.decode("utf-8", errors="ignore")
        if _matches(text, query, pattern, case_sensitive):
            hits.append(SearchHit(entry.resource_type, entry.name, entry.language, "utf8", _offset(entry), _preview(text, query, pattern, case_sensitive)))
        utf16 = entry.data.decode("utf-16le", errors="ignore")
        if _matches(utf16, query, pattern, case_sensitive):
            hits.append(SearchHit(entry.resource_type, entry.name, entry.language, "utf16", _offset(entry), _preview(utf16, query, pattern, case_sensitive)))
    return hits


def _matches(value: str, query: str, pattern: re.Pattern[str] | None, case_sensitive: bool) -> bool:
    if pattern is not None:
        return pattern.search(value) is not None
    return query in value if case_sensitive else query.casefold() in value.casefold()


def _preview(value: str, query: str, pattern: re.Pattern[str] | None, case_sensitive: bool) -> str:
    match = pattern.search(value) if pattern is not None else re.search(re.escape(query), value, 0 if case_sensitive else re.IGNORECASE)
    if match is None:
        return value[:96]
    start = max(0, match.start() - 48)
    return value[start:start + 96]


def _offset(entry: ResourceEntry, relative: int = 0) -> int | None:
    value = (entry.metadata or {}).get("offset")
    return int(value) + relative if isinstance(value, int) else None

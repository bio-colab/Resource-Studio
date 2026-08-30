from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .project import ResourceEntry


@dataclass(frozen=True)
class ResourceIndexItem:
    resource_type: str
    name: str
    language: int | None
    size: int
    sha256: str
    offset: int | None

    @property
    def key(self) -> tuple[str, str, int | None]:
        return self.resource_type, self.name, self.language

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "name": self.name,
            "language": self.language,
            "size": self.size,
            "sha256": self.sha256,
            "offset": self.offset,
        }


@dataclass(frozen=True)
class ResourceIndex:
    items: tuple[ResourceIndexItem, ...]

    @classmethod
    def from_entries(cls, entries: Iterable[ResourceEntry]) -> ResourceIndex:
        items = tuple(
            ResourceIndexItem(
                entry.resource_type,
                entry.name,
                entry.language,
                len(entry.data),
                entry.sha256,
                _offset(entry),
            )
            for entry in sorted(entries, key=lambda value: value.key)
        )
        return cls(items)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.items]

    def find(self, resource_type: str, name: str, language: int | None) -> ResourceIndexItem | None:
        key = (resource_type, name, language)
        return next((item for item in self.items if item.key == key), None)


def _offset(entry: ResourceEntry) -> int | None:
    value = (entry.metadata or {}).get("offset")
    return int(value) if isinstance(value, int) else None

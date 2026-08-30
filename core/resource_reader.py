"""Read-only PE resource access without creating a Project workspace."""

from pathlib import Path

import lief

from .access import path_access_status
from .parse_cache import shared_parse
from .project import ResourceEntry, _entries_from_lief


class ResourceReader:
    """Parse one PE once and expose its resource entries in memory."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser().resolve()
        if not self.path.is_file():
            raise ValueError(f"NOT_FOUND: source file not found: {self.path}")
        access_status = path_access_status(self.path)
        if access_status != "READY":
            raise ValueError(f"{access_status}: cannot read PE source: {self.path}")
        try:
            binary = shared_parse(self.path)
        except Exception as exc:
            raise ValueError(f"MALFORMED_PE: cannot open PE: {exc}") from exc
        if binary is None or not isinstance(binary, lief.PE.Binary):
            raise ValueError("NOT_PE: source is not a supported PE file")
        self._entries = tuple(_entries_from_lief(binary))

    @property
    def entries(self) -> list[ResourceEntry]:
        return list(self._entries)

    def find(
        self,
        resource_type: str | None = None,
        name: str | None = None,
        language: int | None = None,
    ) -> list[ResourceEntry]:
        return [
            entry
            for entry in self._entries
            if (resource_type is None or entry.resource_type == resource_type)
            and (name is None or entry.name == name)
            and (language is None or entry.language == language)
        ]

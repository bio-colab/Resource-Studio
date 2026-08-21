"""Read-only PE resource access without creating a Project workspace."""

from pathlib import Path

import lief

from .project import ResourceEntry, _entries_from_lief


class ResourceReader:
    """Parse one PE once and expose its resource entries in memory."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser().resolve()
        if not self.path.is_file():
            raise ValueError(f"source file not found: {self.path}")
        try:
            binary = lief.parse(str(self.path))
        except Exception as exc:
            raise ValueError(f"cannot open PE: {exc}") from exc
        if binary is None or not isinstance(binary, lief.PE.Binary):
            raise ValueError("source is not a supported PE file")
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

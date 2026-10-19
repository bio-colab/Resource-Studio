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
        self._entries = tuple(_entries_from_lief(binary, path=self.path))

    @property
    def entries(self) -> list[ResourceEntry]:
        all_entries = list(self._entries)
        try:
            managed = self.read_managed_resources()
            if managed:
                all_entries.extend(managed)
        except Exception:
            pass
        return all_entries

    def find(
        self,
        resource_type: str | None = None,
        name: str | int | None = None,
        language: int | None = None,
    ) -> list[ResourceEntry]:
        str_name = str(name) if name is not None else None
        return [
            entry
            for entry in self.entries
            if (resource_type is None or entry.resource_type == resource_type)
            and (str_name is None or entry.name == str_name)
            and (language is None or entry.language == language)
        ]

    def read_mui_companion_entries(self, language: str | None = None) -> list[ResourceEntry]:
        """Discovers companion .mui files in language subdirectories and reads their resources."""
        from .pe_metadata import PEMetadataInspector

        meta = PEMetadataInspector.inspect(self.path)
        if not meta.companion_mui_files:
            return []

        companion_entries: list[ResourceEntry] = []
        for mui_path_str in meta.companion_mui_files:
            p = Path(mui_path_str)
            if language is not None and language.lower() not in p.parent.name.lower():
                continue
            try:
                reader = ResourceReader(p)
                companion_entries.extend(reader.entries)
            except Exception:
                pass
        return companion_entries

    def read_managed_resources(self) -> list[ResourceEntry]:
        """Reads embedded .NET ManifestResource entries and returns them as ResourceEntry items."""
        from .managed_pe import ManagedPEParser

        try:
            parser = ManagedPEParser(self.path)
            report = parser.parse()
            if not report.is_managed or not report.manifest_resources:
                return []

            results: list[ResourceEntry] = []
            for mr in report.manifest_resources:
                results.append(
                    ResourceEntry(
                        resource_type="MANIFEST_RESOURCE",
                        name=mr.name,
                        language=0,
                        data=mr.data,
                    )
                )
            return results
        except Exception:
            return []



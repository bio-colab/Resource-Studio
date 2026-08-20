from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief


_LANGUAGE_PART = re.compile(r"^[A-Za-z]{2,3}(?:[-_][A-Za-z]{2,4})?$")


@dataclass(frozen=True)
class PEMetadataReport:
    path: str
    is_mui: bool
    is_satellite_hint: bool
    language_hint: str | None
    is_dotnet: bool
    clr_directory: dict[str, Any] | None
    resource_separation: dict[str, Any]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "isMui": self.is_mui,
            "isSatelliteHint": self.is_satellite_hint,
            "languageHint": self.language_hint,
            "isDotNet": self.is_dotnet,
            "clrDirectory": dict(self.clr_directory) if self.clr_directory else None,
            "resourceSeparation": dict(self.resource_separation),
            "warnings": list(self.warnings),
        }


class PEMetadataInspector:
    @staticmethod
    def inspect(path: Path) -> PEMetadataReport:
        path = Path(path).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"file not found: {path}")
        try:
            binary = lief.parse(str(path))
        except Exception as exc:
            raise ValueError(f"cannot parse PE: {exc}") from exc
        if binary is None or not isinstance(binary, lief.PE.Binary):
            raise ValueError("input is not a supported PE binary")
        name = path.name.lower()
        is_mui = path.suffix.lower() == ".mui"
        is_satellite = is_mui or name.endswith(".resources.dll")
        language_hint = _language_hint(path)
        clr = _directory_record(binary, 14)
        is_dotnet = bool(clr and clr["size"] > 0)
        warnings: list[str] = []
        if is_dotnet:
            warnings.append("CLR directory detected; metadata tables are read-only and not decoded by this backend")
        if is_mui and language_hint is None:
            warnings.append("MUI filename does not expose a conventional language directory")
        return PEMetadataReport(
            path=str(path),
            is_mui=is_mui,
            is_satellite_hint=is_satellite,
            language_hint=language_hint,
            is_dotnet=is_dotnet,
            clr_directory=clr,
            resource_separation={
                "resourceDirectory": ".rsrc",
                "separateFromClr": True,
                "writeSupported": False,
            },
            warnings=tuple(warnings),
        )


def _directory_record(binary: Any, index: int) -> dict[str, int] | None:
    try:
        directory = binary.data_directory(index)
        rva = int(directory.rva)
        size = int(directory.size)
        return {"index": index, "rva": rva, "size": size, "present": bool(rva or size)}
    except Exception:
        return None


def _language_hint(path: Path) -> str | None:
    for part in reversed(path.parent.parts):
        if _LANGUAGE_PART.fullmatch(part):
            return part.replace("_", "-")
    return None

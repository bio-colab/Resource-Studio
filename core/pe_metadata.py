from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief

from .parse_cache import shared_parse


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
    has_mui_resource: bool = False
    is_mui_base: bool = False
    companion_mui_files: tuple[str, ...] = field(default_factory=tuple)
    base_executable: str | None = None
    managed_metadata: dict[str, Any] | None = None
    toolchain: dict[str, Any] | None = None

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
            "hasMuiResource": self.has_mui_resource,
            "isMuiBase": self.is_mui_base,
            "companionMuiFiles": list(self.companion_mui_files),
            "baseExecutable": self.base_executable,
            "managedMetadata": dict(self.managed_metadata) if self.managed_metadata else None,
            "toolchain": dict(self.toolchain) if self.toolchain else None,
        }


class PEMetadataInspector:
    @staticmethod
    def inspect(path: Path) -> PEMetadataReport:
        path = Path(path).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"file not found: {path}")
        try:
            binary = shared_parse(path)
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

        # Discover MUI resources and companions
        has_mui_resource = False
        if getattr(binary, "has_resources", False) and binary.resources is not None:
            for child in binary.resources.childs:
                if str(child.name).upper() == "MUI" or child.id == 222:
                    has_mui_resource = True
                    break

        companion_mui: list[str] = []
        base_exe: str | None = None
        is_mui_base = False

        if has_mui_resource and not is_mui:
            is_mui_base = True
            try:
                parent = path.parent
                for sub in parent.iterdir():
                    if sub.is_dir() and _LANGUAGE_PART.fullmatch(sub.name):
                        cand = sub / f"{path.name}.mui"
                        if cand.is_file():
                            companion_mui.append(str(cand.resolve()))
            except (OSError, PermissionError):
                pass
        elif is_mui:
            is_mui_base = False
            try:
                base_name = path.name[:-4] if path.name.lower().endswith(".mui") else path.stem
                cand = path.parent.parent / base_name
                if cand.is_file():
                    base_exe = str(cand.resolve())
            except (OSError, PermissionError):
                pass
        # Discover Managed (.NET) Metadata
        managed_meta_dict: dict[str, Any] | None = None
        if is_dotnet:
            try:
                from .managed_pe import ManagedPEParser
                m_rep = ManagedPEParser(path).parse()
                if m_rep.is_managed:
                    managed_meta_dict = m_rep.to_dict()
            except Exception:
                pass

        # Discover Go / Rust / Toolchain Metadata
        toolchain_dict: dict[str, Any] | None = None
        try:
            from .toolchain_auditor import ToolchainAuditor
            t_rep = ToolchainAuditor(path).audit()
            if t_rep.toolchain_type != "NATIVE_WIN32" or t_rep.go_info or t_rep.rust_info:
                toolchain_dict = t_rep.to_dict()
        except Exception:
            pass

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
            has_mui_resource=has_mui_resource,
            is_mui_base=is_mui_base,
            companion_mui_files=tuple(companion_mui),
            base_executable=base_exe,
            managed_metadata=managed_meta_dict,
            toolchain=toolchain_dict,
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

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief


@dataclass(frozen=True)
class PECompatibilityReport:
    path: str
    machine: str
    kind: str
    profiles: tuple[str, ...]
    named_resources: int
    resource_count: int
    overlay_size: int
    has_signature: bool
    has_arm64x: bool
    has_delay_imports: bool
    has_exceptions: bool
    has_load_config: bool
    has_clr: bool
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "machine": self.machine,
            "kind": self.kind,
            "profiles": list(self.profiles),
            "namedResources": self.named_resources,
            "resourceCount": self.resource_count,
            "overlaySize": self.overlay_size,
            "hasSignature": self.has_signature,
            "hasArm64x": self.has_arm64x,
            "hasDelayImports": self.has_delay_imports,
            "hasExceptions": self.has_exceptions,
            "hasLoadConfig": self.has_load_config,
            "hasClr": self.has_clr,
            "warnings": list(self.warnings),
        }


def inspect_compatibility(path: Path) -> PECompatibilityReport:
    path = Path(path).expanduser().resolve()
    binary = lief.parse(str(path))
    if binary is None or not isinstance(binary, lief.PE.Binary):
        raise ValueError(f"not a supported PE: {path}")
    machine = str(binary.header.machine)
    is_dll = binary.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
    kind = "DLL" if is_dll else "EXE"
    if str(getattr(binary.optional_header, "subsystem", "")) == "SUBSYSTEM.WINDOWS_CUI" and not is_dll:
        kind = "EXE/CUI"
    resource_count = 0
    named_resources = 0
    if binary.has_resources:
        for type_node in binary.resources.childs:
            for name_node in type_node.childs:
                resource_count += len(tuple(name_node.childs))
                if bool(getattr(name_node, "has_name", False)):
                    named_resources += 1
    overlay_size = len(bytes(binary.overlay))
    has_arm64x = bool(getattr(binary, "is_arm64x", False) or getattr(binary, "is_arm64ec", False))
    has_clr = bool(getattr(binary, "has_dotnet", False) or getattr(binary, "clr_runtime_header", None))
    profiles = [machine, kind]
    if has_arm64x:
        profiles.append("ARM64X/ARM64EC")
    if binary.has_signatures:
        profiles.append("Authenticode")
    warnings: list[str] = []
    if overlay_size:
        warnings.append("overlay present; resource-only verification must preserve it")
    if has_arm64x:
        warnings.append("ARM64X/ARM64EC requires parser configuration and dedicated round-trip fixtures")
    if has_clr:
        warnings.append("CLR metadata detected; managed resource tables are not decoded by the core")
    return PECompatibilityReport(
        path=str(path), machine=machine, kind=kind, profiles=tuple(profiles), named_resources=named_resources,
        resource_count=resource_count, overlay_size=overlay_size, has_signature=bool(binary.has_signatures),
        has_arm64x=has_arm64x, has_delay_imports=bool(binary.has_delay_imports), has_exceptions=bool(binary.has_exceptions),
        has_load_config=bool(binary.has_configuration), has_clr=has_clr, warnings=tuple(warnings),
    )

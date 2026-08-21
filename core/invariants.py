from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief


@dataclass(frozen=True)
class PEInvariantSnapshot:
    machine: str
    imagebase: int
    entrypoint: int
    sections: tuple[dict[str, Any], ...]
    directories: tuple[dict[str, Any], ...]
    imports: tuple[dict[str, Any], ...]
    exports: tuple[dict[str, Any], ...]
    overlay: dict[str, Any]
    tls: dict[str, Any] | None
    load_config: dict[str, Any] | None
    debug: tuple[dict[str, Any], ...]
    resources: tuple[dict[str, Any], ...]
    resource_issues: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "machine": self.machine,
            "imagebase": self.imagebase,
            "entrypoint": self.entrypoint,
            "sections": [dict(item) for item in self.sections],
            "directories": [dict(item) for item in self.directories],
            "imports": [dict(item) for item in self.imports],
            "exports": [dict(item) for item in self.exports],
            "overlay": dict(self.overlay),
            "tls": dict(self.tls) if self.tls else None,
            "loadConfig": dict(self.load_config) if self.load_config else None,
            "debug": [dict(item) for item in self.debug],
            "resources": [dict(item) for item in self.resources],
            "resourceIssues": list(self.resource_issues),
        }


@dataclass(frozen=True)
class PESurgicalChangeReport:
    valid: bool
    violations: tuple[str, ...]
    before: PEInvariantSnapshot
    after: PEInvariantSnapshot

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "violations": list(self.violations),
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
        }


def snapshot(path: Path, *, binary: Any | None = None) -> PEInvariantSnapshot:
    path = Path(path).expanduser().resolve()
    binary = binary if binary is not None else lief.parse(str(path))
    if binary is None or not isinstance(binary, lief.PE.Binary):
        raise ValueError(f"not a supported PE: {path}")
    resource_section = _resource_section(binary)
    sections = []
    for section in binary.sections:
        item = {
            "name": str(section.name),
            "virtualAddress": int(section.virtual_address),
            "rawOffset": int(section.pointerto_raw_data),
            "characteristics": int(section.characteristics),
            "isResource": str(section.name) == resource_section,
        }
        if str(section.name) != resource_section:
            item.update({"virtualSize": int(section.virtual_size), "rawSize": int(section.sizeof_raw_data)})
        sections.append(item)
    directories = []
    for directory in binary.data_directories:
        kind = str(directory.type)
        if kind.endswith("RESOURCE_TABLE"):
            continue
        directories.append({"type": kind, "rva": int(directory.rva), "size": int(directory.size)})
    resources, resource_issues = _resources(binary, path.stat().st_size)
    return PEInvariantSnapshot(
        machine=str(binary.header.machine),
        imagebase=int(binary.optional_header.imagebase),
        entrypoint=int(binary.optional_header.addressof_entrypoint),
        sections=tuple(sections),
        directories=tuple(directories),
        imports=tuple(_imports(binary)),
        exports=tuple(_exports(binary)),
        overlay={"offset": int(binary.overlay_offset), "size": len(bytes(binary.overlay)), "sha256": hashlib.sha256(bytes(binary.overlay)).hexdigest()},
        tls=_tls(binary),
        load_config=_load_config(binary),
        debug=tuple(_debug(binary)),
        resources=tuple(resources),
        resource_issues=tuple(resource_issues),
    )


def compare_surgical_change(
    before_path: Path,
    after_path: Path,
    *,
    before_snapshot: PEInvariantSnapshot | None = None,
    after_snapshot: PEInvariantSnapshot | None = None,
) -> PESurgicalChangeReport:
    before = before_snapshot or snapshot(before_path)
    after = after_snapshot or snapshot(after_path)
    violations: list[str] = []
    for field in ("machine", "imagebase", "entrypoint", "directories", "imports", "exports", "overlay", "tls", "load_config", "debug"):
        if getattr(before, field) != getattr(after, field):
            violations.append(field)
    before_non_resource = tuple(item for item in before.sections if not item["isResource"])
    after_non_resource = tuple(item for item in after.sections if not item["isResource"])
    if before_non_resource != after_non_resource:
        violations.append("sections")
    if set(after.resource_issues) - set(before.resource_issues):
        violations.append("resource_tree")
    return PESurgicalChangeReport(not violations, tuple(violations), before, after)


def _resource_section(binary: Any) -> str:
    try:
        directory = binary.data_directory(lief.PE.DataDirectory.TYPES.RESOURCE_TABLE)
        section = getattr(directory, "section", None)
        name = getattr(section, "name", None)
        return str(name) if name else ""
    except Exception:
        return ""


def _resources(binary: Any, file_size: int) -> tuple[list[dict[str, Any]], list[str]]:
    type_names = {
        1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
        7: "FONTDIR", 8: "FONT", 9: "ACCELERATORS", 10: "RCDATA", 11: "MESSAGETABLE",
        12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST",
    }
    if not binary.has_resources:
        return [], []
    result: list[dict[str, Any]] = []
    issues: list[str] = []
    seen: set[tuple[str, str, int]] = set()
    for type_node in binary.resources.childs:
        resource_type = type_names.get(int(type_node.id), str(type_node.id))
        for name_node in type_node.childs:
            resource_name = str(name_node.name) if getattr(name_node, "has_name", False) else str(name_node.id)
            for leaf in name_node.childs:
                language = int(leaf.id) if isinstance(leaf.id, int) else -1
                data = bytes(leaf.content)
                offset = int(getattr(leaf, "offset", 0))
                key = (resource_type, resource_name, language)
                item = {
                    "type": resource_type,
                    "name": resource_name,
                    "language": language,
                    "offset": offset,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "codePage": int(getattr(leaf, "code_page", 0)),
                }
                result.append(item)
                if key in seen:
                    issues.append(f"duplicate resource leaf: {resource_type}:{resource_name}:{language}")
                seen.add(key)
                if language < 0 or language > 0xFFFF:
                    issues.append(f"resource language outside WORD: {resource_type}:{resource_name}:{language}")
                if offset < 0 or offset + len(data) > file_size:
                    issues.append(f"resource data outside file bounds: {resource_type}:{resource_name}:{language}")
    result.sort(key=lambda item: (item["type"], item["name"], item["language"]))
    return result, issues


def _imports(binary: Any) -> list[dict[str, Any]]:
    result = []
    for library in binary.imports:
        result.append({"name": str(library.name), "entries": tuple((str(entry.name), int(entry.ordinal), bool(entry.is_ordinal)) for entry in library.entries)})
    return result


def _exports(binary: Any) -> list[dict[str, Any]]:
    result = []
    for item in getattr(binary, "exported_functions", []):
        result.append(
            {
                "name": str(getattr(item, "name", "")),
                "address": _numeric(getattr(item, "address", 0)),
                "ordinal": _numeric(getattr(item, "ordinal", 0)),
                "forwarder": bool(getattr(item, "is_forwarder", False)),
            }
        )
    return result


def _tls(binary: Any) -> dict[str, Any] | None:
    value = getattr(binary, "tls", None)
    if value is None:
        return None
    return {"callbacks": _numeric(getattr(value, "addressof_callbacks", 0)), "index": _numeric(getattr(value, "addressof_index", 0)), "rawData": _numeric(getattr(value, "addressof_raw_data", 0)), "zeroFill": _numeric(getattr(value, "sizeof_zero_fill", 0)), "characteristics": _numeric(getattr(value, "characteristics", 0))}


def _numeric(value: Any, default: int = 0) -> int:
    if isinstance(value, (tuple, list)):
        return _numeric(value[0], default) if value else default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _load_config(binary: Any) -> dict[str, Any] | None:
    value = getattr(binary, "load_configuration", None)
    if value is None:
        return None
    result = {}
    for name in ("size", "timestamp", "guard_flags", "security_cookie", "se_handler_table", "se_handler_count"):
        if hasattr(value, name):
            try:
                result[name] = int(getattr(value, name))
            except Exception:
                result[name] = str(getattr(value, name))
    return result


def _debug(binary: Any) -> list[dict[str, Any]]:
    result = []
    for item in binary.debug:
        result.append({"type": str(getattr(item, "type", "")), "timestamp": int(getattr(item, "timestamp", 0)), "raw": int(getattr(item, "pointerto_rawdata", 0)), "size": int(getattr(item, "sizeof_data", 0)), "filename": str(getattr(item, "filename", ""))})
    return result

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .commands import CommandHistory
from .project import Project, ResourceEntry

PLUGIN_API = "resource-editor/v1"
HOST_VERSION = "1.0.0"
ALLOWED_PERMISSIONS = frozenset(
    {
        "project.read",
        "project.modify",
        "files.read",
        "files.write.project-output",
        "network",
        "process.execute",
        "clipboard.read",
        "clipboard.write",
    }
)
_PLUGIN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_API = re.compile(r"^resource-editor/v(\d+)$")
_ENTRYPOINT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class ResourceTypeDefinition:
    type_name: str
    plugin_id: str
    parser: str
    viewer: str
    serializer: str | None = None
    read_only: bool = True

    def __post_init__(self) -> None:
        if not self.type_name or len(self.type_name) > 64:
            raise ValueError("resource type name must be 1-64 characters")
        for label, value in (("parser", self.parser), ("viewer", self.viewer), ("serializer", self.serializer)):
            if value is not None and not _ENTRYPOINT.fullmatch(value):
                raise ValueError(f"invalid {label} entrypoint")


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    api: str
    entry: str
    permissions: frozenset[str]
    kind: str = "viewer"
    ui: dict[str, Any] | None = None
    min_host_version: str | None = None
    max_host_version: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> PluginManifest:
        required = {"id", "name", "version", "api", "entry", "permissions"}
        missing = sorted(required - payload.keys())
        if missing:
            raise ValueError(f"plugin manifest missing fields: {', '.join(missing)}")
        plugin_id = str(payload["id"])
        version = str(payload["version"])
        permissions = frozenset(str(item) for item in payload["permissions"])
        if not _PLUGIN_ID.fullmatch(plugin_id):
            raise ValueError("plugin id must be lowercase and 2-64 characters")
        if not _VERSION.fullmatch(version):
            raise ValueError("plugin version must be semantic version x.y.z")
        api = str(payload["api"])
        if api != PLUGIN_API:
            raise ValueError(f"unsupported plugin API: {api}")
        unknown = permissions - ALLOWED_PERMISSIONS
        if unknown:
            raise ValueError(f"unknown permissions: {', '.join(sorted(unknown))}")
        kind = str(payload.get("kind", "viewer"))
        if kind not in {"viewer", "editor", "importer", "exporter", "parser", "panel", "automation"}:
            raise ValueError(f"unsupported plugin kind: {kind}")
        min_host_version = payload.get("minHostVersion")
        max_host_version = payload.get("maxHostVersion")
        for label, candidate in (("minHostVersion", min_host_version), ("maxHostVersion", max_host_version)):
            if candidate is not None and not _VERSION.fullmatch(str(candidate)):
                raise ValueError(f"{label} must be semantic version x.y.z")
        if min_host_version is not None and max_host_version is not None:
            if _version_tuple(str(min_host_version)) > _version_tuple(str(max_host_version)):
                raise ValueError("minHostVersion cannot exceed maxHostVersion")
        return cls(
            plugin_id=plugin_id,
            name=str(payload["name"]),
            version=version,
            api=api,
            entry=str(payload["entry"]),
            permissions=permissions,
            kind=kind,
            ui=payload.get("ui") or {},
            min_host_version=str(min_host_version) if min_host_version is not None else None,
            max_host_version=str(max_host_version) if max_host_version is not None else None,
        )

    @classmethod
    def load(cls, path: Path) -> PluginManifest:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


class PluginRegistry:
    """Manifest registry with compatibility checks and durable quarantine."""

    def __init__(self, *, audit_path: Path | None = None, host_version: str = HOST_VERSION) -> None:
        if not _VERSION.fullmatch(host_version):
            raise ValueError("host_version must be semantic version x.y.z")
        self._manifests: dict[str, PluginManifest] = {}
        self._resource_types: dict[str, ResourceTypeDefinition] = {}
        self._disabled: dict[str, str] = {}
        self._audit = AuditLog(audit_path) if audit_path is not None else None
        self.host_version = host_version

    def register(self, manifest: PluginManifest) -> None:
        if manifest.plugin_id in self._manifests:
            raise ValueError(f"plugin already registered: {manifest.plugin_id}")
        compatible, reason = self.compatibility(manifest)
        if not compatible:
            raise ValueError(f"incompatible plugin {manifest.plugin_id}: {reason}")
        self._manifests[manifest.plugin_id] = manifest

    def register_file(self, path: Path) -> PluginManifest:
        manifest = PluginManifest.load(path)
        self.register(manifest)
        return manifest

    def register_resource_type(self, definition: ResourceTypeDefinition) -> None:
        self.ensure_registered(definition.plugin_id)
        self.ensure_enabled(definition.plugin_id)
        if definition.type_name in self._resource_types:
            raise ValueError(f"resource type already registered: {definition.type_name}")
        self._resource_types[definition.type_name] = definition
        self.log(definition.plugin_id, "resource-type.register", resourceType=definition.type_name)

    def resource_type(self, type_name: str) -> ResourceTypeDefinition:
        try:
            definition = self._resource_types[type_name]
        except KeyError as exc:
            raise KeyError(f"resource type not registered: {type_name}") from exc
        self.ensure_enabled(definition.plugin_id)
        return definition

    def resource_types(self) -> tuple[ResourceTypeDefinition, ...]:
        return tuple(self._resource_types[key] for key in sorted(self._resource_types))

    def get(self, plugin_id: str) -> PluginManifest:
        try:
            return self._manifests[plugin_id]
        except KeyError as exc:
            raise KeyError(f"plugin not registered: {plugin_id}") from exc

    def list(self) -> tuple[PluginManifest, ...]:
        return tuple(self._manifests[key] for key in sorted(self._manifests))

    def can(self, plugin_id: str, permission: str) -> bool:
        return permission in self.get(plugin_id).permissions

    def compatibility(self, manifest: PluginManifest) -> tuple[bool, str]:
        api_match = _API.fullmatch(manifest.api)
        if api_match is None or int(api_match.group(1)) != 1:
            return False, f"API {manifest.api} is not supported by {PLUGIN_API}"
        host = _version_tuple(self.host_version)
        if manifest.min_host_version and host < _version_tuple(manifest.min_host_version):
            return False, f"requires host >= {manifest.min_host_version}"
        if manifest.max_host_version and host > _version_tuple(manifest.max_host_version):
            return False, f"requires host <= {manifest.max_host_version}"
        return True, "compatible"

    def ensure_compatible(self, plugin_id: str) -> None:
        manifest = self.get(plugin_id)
        compatible, reason = self.compatibility(manifest)
        if not compatible:
            raise RuntimeError(f"plugin incompatible: {plugin_id}: {reason}")

    def is_enabled(self, plugin_id: str) -> bool:
        return plugin_id in self._manifests and plugin_id not in self._disabled

    def disabled_reason(self, plugin_id: str) -> str | None:
        return self._disabled.get(plugin_id)

    def ensure_enabled(self, plugin_id: str) -> None:
        if plugin_id not in self._manifests:
            raise KeyError(f"plugin not registered: {plugin_id}")
        self.ensure_compatible(plugin_id)
        if plugin_id in self._disabled:
            raise RuntimeError(f"plugin disabled: {plugin_id}: {self._disabled[plugin_id]}")

    def disable(self, plugin_id: str, reason: str) -> None:
        self.ensure_registered(plugin_id)
        if plugin_id in self._disabled:
            return
        self._disabled[plugin_id] = reason
        if self._audit is not None:
            self._audit.append("plugin.disabled", pluginId=plugin_id, reason=reason)

    def enable(self, plugin_id: str) -> None:
        self.ensure_registered(plugin_id)
        self._disabled.pop(plugin_id, None)
        if self._audit is not None:
            self._audit.append("plugin.enabled", pluginId=plugin_id)

    def ensure_registered(self, plugin_id: str) -> None:
        if plugin_id not in self._manifests:
            raise KeyError(f"plugin not registered: {plugin_id}")

    def log(self, plugin_id: str, operation: str, **details: Any) -> None:
        self.ensure_enabled(plugin_id)
        if self._audit is not None:
            self._audit.append("plugin.event", pluginId=plugin_id, event=operation, **details)


class PluginContext:
    def __init__(self, registry: PluginRegistry, plugin_id: str, *, project: Project | None = None, history: CommandHistory | None = None) -> None:
        self._registry = registry
        self.plugin_id = plugin_id
        self._project = project
        self._history = history

    def require(self, permission: str) -> None:
        self._registry.ensure_enabled(self.plugin_id)
        if not self._registry.can(self.plugin_id, permission):
            raise PermissionError(f"plugin {self.plugin_id} lacks permission {permission}")

    @property
    def manifest(self) -> PluginManifest:
        self._registry.ensure_enabled(self.plugin_id)
        return self._registry.get(self.plugin_id)

    @property
    def resources(self) -> tuple[ResourceEntry, ...]:
        self.require("project.read")
        return tuple(self._project.entries.values()) if self._project is not None else ()

    def get_resource(self, resource_type: str, name: str, language: int | None) -> ResourceEntry | None:
        self.require("project.read")
        return self._project.get(resource_type, name, language) if self._project is not None else None

    def read_resource(self, resource_type: str, name: str, language: int | None) -> bytes:
        entry = self.get_resource(resource_type, name, language)
        if entry is None:
            raise KeyError(f"resource not found: {(resource_type, name, language)}")
        return bytes(entry.data)

    def put_resource(self, entry: ResourceEntry) -> None:
        self.require("project.modify")
        if self._project is None:
            raise RuntimeError("plugin context has no project")
        self._project.put(entry)
        self._registry.log(self.plugin_id, "resource.put", resourceKey=entry.key)

    def execute_command(self, command: Any) -> None:
        self.require("project.modify")
        if self._project is None:
            raise RuntimeError("plugin context has no project")
        command_project = getattr(command, "project", self._project)
        if command_project is not self._project:
            raise ValueError("plugin command targets a different project")
        if self._history is None:
            command.execute()
        else:
            self._history.execute(command)
        self._registry.log(self.plugin_id, "command.execute", description=getattr(command, "description", type(command).__name__))

    def undo_command(self) -> None:
        self.require("project.modify")
        if self._history is None:
            raise RuntimeError("plugin context has no command history")
        self._history.undo()
        self._registry.log(self.plugin_id, "command.undo")

    def log(self, operation: str, **details: Any) -> None:
        self._registry.log(self.plugin_id, operation, **details)


def _version_tuple(version: str) -> tuple[int, int, int]:
    core = version.split("+", 1)[0].split("-", 1)[0]
    return tuple(int(part) for part in core.split("."))  # type: ignore[return-value]

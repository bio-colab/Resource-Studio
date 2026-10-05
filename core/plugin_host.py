from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import resource as _resource
except ImportError:
    _resource = None

from .plugins import PluginManifest, PluginRegistry
from .windows_isolation import WindowsJob, WindowsJobLimits, WindowsIsolationError


class PluginHostError(RuntimeError):
    pass


ADMIN_RUNTIME_PERMISSIONS = frozenset(
    {
        "project.modify",
        "files.write.project-output",
        "network",
        "process.execute",
        "clipboard.read",
        "clipboard.write",
    }
)
UNSUPPORTED_RUNTIME_PERMISSIONS = frozenset(
    {
        "files.write.project-output",
        "network",
        "process.execute",
        "clipboard.read",
        "clipboard.write",
    }
)
SUPPORTED_RUNTIME_PERMISSIONS = frozenset({"project.read"})


@dataclass(frozen=True)
class PluginLimits:
    max_request_bytes: int = 1_048_576
    max_output_bytes: int = 4_194_304
    max_memory_bytes: int | None = 256 * 1024 * 1024
    max_cpu_seconds: int | None = 5


@dataclass(frozen=True)
class PluginResult:
    plugin_id: str
    response: dict[str, Any]
    stderr: str


class PluginHost:
    """One-shot out-of-process JSON-lines runner with bounded staging and grants."""

    def dry_run_registered(
        self,
        registry: PluginRegistry,
        plugin_id: str,
        plugin_dir: Path,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        registry.ensure_enabled(plugin_id)
        manifest = registry.get(plugin_id)
        plugin_dir = Path(plugin_dir).expanduser().resolve()
        entry = (plugin_dir / manifest.entry).resolve()
        if entry != plugin_dir and plugin_dir not in entry.parents:
            raise PluginHostError("plugin entry is outside plugin directory")
        if entry.is_symlink() or not entry.is_file():
            raise PluginHostError("plugin entry is not a regular file")
        _reject_symlinks(plugin_dir)
        try:
            json.dumps(request, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise PluginHostError("dry-run request is not JSON serializable") from exc
        return {
            "pluginId": plugin_id,
            "entry": str(entry),
            "permissions": sorted(manifest.permissions),
            "request": request,
            "wouldExecute": False,
            "reason": "dry-run only; no plugin process was started",
        }

    def run_registered(
        self,
        registry: PluginRegistry,
        plugin_id: str,
        plugin_dir: Path,
        request: dict[str, Any],
        *,
        granted_permissions: Iterable[str] = (),
        admin_authorized: bool = False,
        timeout_seconds: float = 5.0,
        limits: PluginLimits | None = None,
    ) -> PluginResult:
        registry.ensure_enabled(plugin_id)
        manifest = registry.get(plugin_id)
        grants = _validate_grants(manifest, granted_permissions, admin_authorized)
        try:
            result = self.run(
                manifest,
                plugin_dir,
                request,
                granted_permissions=grants,
                timeout_seconds=timeout_seconds,
                limits=limits,
            )
            registry.log(plugin_id, "runtime.execute", grantedPermissions=sorted(grants))
            return result
        except PluginHostError as exc:
            registry.disable(plugin_id, str(exc))
            raise

    def run(
        self,
        manifest: PluginManifest,
        plugin_dir: Path,
        request: dict[str, Any],
        *,
        granted_permissions: Iterable[str] = (),
        timeout_seconds: float = 5.0,
        limits: PluginLimits | None = None,
    ) -> PluginResult:
        limits = limits or PluginLimits()
        grants = frozenset(str(permission) for permission in granted_permissions)
        if not grants.issubset(manifest.permissions):
            raise PluginHostError("runtime grant contains a permission not declared by the manifest")
        if not grants.issubset(SUPPORTED_RUNTIME_PERMISSIONS):
            raise PluginHostError("runtime permission requires an unavailable sandbox adapter")
        plugin_dir = Path(plugin_dir).expanduser().resolve()
        entry = (plugin_dir / manifest.entry).resolve()
        if entry != plugin_dir and plugin_dir not in entry.parents:
            raise PluginHostError("plugin entry is outside plugin directory")
        if entry.is_symlink() or not entry.is_file():
            raise PluginHostError("plugin entry is not a regular file")
        _reject_symlinks(plugin_dir)
        serialized_request = json.dumps(request, ensure_ascii=False) + "\n"
        if len(serialized_request.encode("utf-8")) > limits.max_request_bytes:
            raise PluginHostError("plugin request exceeds configured size limit")
        environment = {
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": "",
            "RESOURCE_STUDIO_PLUGIN_ID": manifest.plugin_id,
            "RESOURCE_STUDIO_PLUGIN_PERMISSIONS": json.dumps(sorted(grants), separators=(",", ":")),
        }
        with tempfile.TemporaryDirectory(prefix="resource-studio-plugin-run-") as temporary:
            staged_dir = Path(temporary) / "plugin"
            shutil.copytree(plugin_dir, staged_dir, symlinks=False)
            staged_entry = (staged_dir / manifest.entry).resolve()
            if staged_entry != staged_dir and staged_dir not in staged_entry.parents:
                raise PluginHostError("staged plugin entry is outside plugin directory")
            command = [sys.executable, "-I", "-S", str(staged_entry)] if entry.suffix == ".py" else [str(staged_entry)]
            try:
                if os.name == "nt":
                    with WindowsJob(WindowsJobLimits(max_processes=1, max_memory_bytes=limits.max_memory_bytes)) as job:
                        process = subprocess.Popen(
                            command,
                            cwd=staged_dir,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            shell=False,
                            env=environment,
                            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                        )
                        job.assign(process)
                        try:
                            stdout, stderr = process.communicate(serialized_request, timeout=timeout_seconds)
                        except subprocess.TimeoutExpired:
                            job.terminate()
                            stdout, stderr = process.communicate()
                            raise
                        completed = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                else:
                    completed = subprocess.run(
                        command,
                        cwd=staged_dir,
                        input=serialized_request,
                        text=True,
                        capture_output=True,
                        timeout=timeout_seconds,
                        check=False,
                        shell=False,
                        env=environment,
                        preexec_fn=_make_limit_fn(limits),
                    )
            except subprocess.TimeoutExpired as exc:
                raise PluginHostError(f"plugin timed out after {timeout_seconds}s") from exc
            except WindowsIsolationError as exc:
                raise PluginHostError(f"plugin Windows isolation failed: {exc}") from exc
        if completed.returncode != 0:
            raise PluginHostError(f"plugin exited with {completed.returncode}: {completed.stderr.strip()}")
        if len(completed.stdout.encode("utf-8")) > limits.max_output_bytes:
            raise PluginHostError("plugin output exceeds configured size limit")
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            raise PluginHostError("plugin must return exactly one JSON response line")
        try:
            response = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise PluginHostError("plugin response is not valid JSON") from exc
        if not isinstance(response, dict):
            raise PluginHostError("plugin response must be a JSON object")
        return PluginResult(manifest.plugin_id, response, completed.stderr)


def _reject_symlinks(plugin_dir: Path) -> None:
    for path in plugin_dir.rglob("*"):
        if path.is_symlink():
            raise PluginHostError("plugin trees containing symbolic links are rejected")


def _validate_grants(manifest: PluginManifest, permissions: Iterable[str], admin_authorized: bool) -> frozenset[str]:
    grants = frozenset(str(permission) for permission in permissions)
    if not grants.issubset(manifest.permissions):
        raise PluginHostError("runtime grant contains a permission not declared by the manifest")
    if grants & ADMIN_RUNTIME_PERMISSIONS and not admin_authorized:
        raise PluginHostError("admin authorization is required for the requested plugin permissions")
    unsupported = grants & UNSUPPORTED_RUNTIME_PERMISSIONS
    if unsupported:
        raise PluginHostError("runtime sandbox adapter is not enabled for: " + ", ".join(sorted(unsupported)))
    if not grants.issubset(SUPPORTED_RUNTIME_PERMISSIONS):
        raise PluginHostError("runtime permission is not supported by the current plugin context")
    return grants


def _make_limit_fn(limits: PluginLimits):
    if _resource is None:
        return None

    def limit_process() -> None:
        if limits.max_memory_bytes is not None:
            _resource.setrlimit(_resource.RLIMIT_AS, (limits.max_memory_bytes, limits.max_memory_bytes))
        if limits.max_cpu_seconds is not None:
            _resource.setrlimit(_resource.RLIMIT_CPU, (limits.max_cpu_seconds, limits.max_cpu_seconds))

    return limit_process

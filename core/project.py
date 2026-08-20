from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .audit import AuditLog


@dataclass
class ResourceEntry:
    resource_type: str
    name: str
    language: int | None
    data: bytes
    metadata: dict[str, Any] | None = None

    @property
    def key(self) -> tuple[str, str, int | None]:
        return (self.resource_type, self.name, self.language)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def descriptor(self, data_file: str) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "name": self.name,
            "language": self.language,
            "size": len(self.data),
            "sha256": self.sha256,
            "dataFile": data_file,
            "metadata": self.metadata or {},
        }


class Project:
    """Portable project state; it never writes the original input file."""

    FORMAT = "resource_studio.project.v1"

    def __init__(
        self,
        project_dir: Path,
        *,
        original_path: str | None = None,
        original_sha256: str | None = None,
        entries: Iterable[ResourceEntry] = (),
    ) -> None:
        self.project_dir = Path(project_dir).expanduser().resolve()
        self.original_path = original_path
        self.original_sha256 = original_sha256
        self.entries: dict[tuple[str, str, int | None], ResourceEntry] = {entry.key: entry for entry in entries}
        self.dirty = False

    @property
    def project_file(self) -> Path:
        return self.project_dir / "project.json"

    @property
    def workspace_dir(self) -> Path:
        return self.project_dir / "workspace"

    @property
    def workspace_path(self) -> Path | None:
        if not self.original_path:
            return None
        return self.workspace_dir / Path(self.original_path).name

    @property
    def outputs_dir(self) -> Path:
        return self.project_dir / "outputs"

    @property
    def audit(self) -> AuditLog:
        return AuditLog(self.project_dir / "audit.jsonl")

    @property
    def resources_dir(self) -> Path:
        return self.project_dir / "resources"

    @property
    def snapshots_dir(self) -> Path:
        return self.project_dir / "snapshots"

    @property
    def lock_file(self) -> Path:
        return self.project_dir / ".project.lock"

    def acquire_lock(self) -> Path:
        self.project_dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"pid": os.getpid(), "project": str(self.project_dir)}) + "\n"
        try:
            descriptor = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise RuntimeError(f"project is locked: {self.lock_file}") from exc
        try:
            os.write(descriptor, payload.encode("utf-8"))
        finally:
            os.close(descriptor)
        return self.lock_file

    def release_lock(self) -> None:
        self.lock_file.unlink(missing_ok=True)

    @contextmanager
    def locked(self):
        self.acquire_lock()
        try:
            yield self
        finally:
            self.release_lock()

    def find_resources(self, resource_type: str | None = None, language: int | None = None) -> list[ResourceEntry]:
        return [
            entry
            for entry in self.entries.values()
            if (resource_type is None or entry.resource_type == resource_type)
            and (language is None or entry.language == language)
        ]

    def index_resources(self):
        from .resource_index import ResourceIndex

        return ResourceIndex.from_entries(self.entries.values())

    def get(self, resource_type: str, name: str, language: int | None) -> ResourceEntry | None:
        return self.entries.get((resource_type, name, language))

    def put(self, entry: ResourceEntry) -> None:
        self.entries[entry.key] = entry
        self.dirty = True

    def remove(self, resource_type: str, name: str, language: int | None) -> ResourceEntry:
        try:
            entry = self.entries.pop((resource_type, name, language))
        except KeyError as exc:
            raise KeyError(f"resource not found: {(resource_type, name, language)}") from exc
        self.dirty = True
        return entry

    @classmethod
    def open_pe(cls, source_path: Path, project_dir: Path) -> Project:
        source_path = Path(source_path).expanduser().resolve()
        if not source_path.is_file():
            raise ValueError(f"source file not found: {source_path}")
        try:
            import lief

            binary = lief.parse(str(source_path))
        except Exception as exc:
            raise ValueError(f"cannot open PE: {exc}") from exc
        if binary is None or not isinstance(binary, lief.PE.Binary):
            raise ValueError("source is not a supported PE file")
        entries = _entries_from_lief(binary)
        project = cls(
            project_dir,
            original_path=str(source_path),
            original_sha256=_sha256_bytes(source_path.read_bytes()),
            entries=entries,
        )
        workspace_path = project.workspace_path
        assert workspace_path is not None
        _atomic_copy(source_path, workspace_path)
        project.save()
        project.audit.append("project.open_pe", originalPath=str(source_path), originalSha256=project.original_sha256, resourceCount=len(entries))
        return project

    def save_as(self, output_path: Path) -> Path:
        if self.workspace_path is None or not self.workspace_path.is_file():
            raise ValueError("project has no isolated PE workspace")
        output_path = Path(output_path).expanduser().resolve()
        _atomic_copy(self.workspace_path, output_path)
        self.audit.append("project.save_as", outputPath=str(output_path), workspaceSha256=_sha256_bytes(self.workspace_path.read_bytes()))
        return output_path

    def export_git(self, output_dir: Path) -> Path:
        """Export only portable project metadata/resources for source control."""
        output_dir = Path(output_dir).expanduser().resolve()
        if output_dir == self.project_dir:
            raise ValueError("export destination cannot be the project directory")
        self.save()
        output_dir.mkdir(parents=True, exist_ok=True)
        _atomic_copy(self.project_file, output_dir / "project.json")
        if self.resources_dir.is_dir():
            shutil.copytree(self.resources_dir, output_dir / "resources", dirs_exist_ok=True)
        if self.workspace_path is not None and self.workspace_path.is_file():
            _atomic_copy(self.workspace_path, output_dir / "workspace" / self.workspace_path.name)
        if self.snapshots_dir.is_dir():
            shutil.copytree(self.snapshots_dir, output_dir / "snapshots", dirs_exist_ok=True)
        self.audit.append("project.export_git", outputPath=str(output_dir), resourceCount=len(self.entries))
        return output_dir

    @classmethod
    def import_git(cls, source_dir: Path, project_dir: Path) -> Project:
        source_dir = Path(source_dir).expanduser().resolve()
        project_dir = Path(project_dir).expanduser().resolve()
        if source_dir == project_dir:
            raise ValueError("import source and destination must differ")
        source_file = source_dir / "project.json"
        if not source_file.is_file():
            raise ValueError(f"portable project.json not found: {source_file}")
        project_dir.mkdir(parents=True, exist_ok=True)
        _atomic_copy(source_file, project_dir / "project.json")
        for directory in ("resources", "snapshots"):
            source_subdir = source_dir / directory
            if source_subdir.is_dir():
                shutil.copytree(source_subdir, project_dir / directory, dirs_exist_ok=True)
        project = cls.load(project_dir)
        if project.workspace_path is None:
            raise ValueError("portable project has no original PE path")
        source_workspace = source_dir / "workspace" / project.workspace_path.name
        if not source_workspace.is_file():
            raise ValueError(f"portable workspace not found: {source_workspace}")
        _atomic_copy(source_workspace, project.workspace_path)
        from .pe_writer import LiefPEWriter

        actual = _entries_from_lief(LiefPEWriter()._parse(project.workspace_path))
        if {(entry.key, entry.sha256) for entry in actual} != {(entry.key, entry.sha256) for entry in project.entries.values()}:
            raise ValueError("portable workspace failed resource verification")
        project.audit.append("project.import_git", sourcePath=str(source_dir), resourceCount=len(project.entries), verified=True)
        return project

    def build(self, output_path: Path) -> Path:
        """Build the isolated workspace after validating project descriptors and PE round-trip."""
        if self.workspace_path is None or not self.workspace_path.is_file():
            raise ValueError("project has no isolated PE workspace")
        if self.original_path and self.original_sha256:
            original = Path(self.original_path)
            if original.is_file() and _sha256_bytes(original.read_bytes()) != self.original_sha256:
                raise ValueError("original input changed since project was opened")
        from .health import PEHealth
        from .pe_writer import LiefPEWriter

        workspace_entries = _entries_from_lief(LiefPEWriter()._parse(self.workspace_path))
        expected = {(entry.key, entry.sha256) for entry in self.entries.values()}
        actual = {(entry.key, entry.sha256) for entry in workspace_entries}
        if expected != actual:
            raise ValueError("project resources do not match the isolated PE workspace")
        output = self.save_as(output_path)
        report = PEHealth.inspect(output)
        if not report.is_pe:
            raise ValueError("build output is not a supported PE")
        reopened_entries = _entries_from_lief(LiefPEWriter()._parse(output))
        if {(entry.key, entry.sha256) for entry in reopened_entries} != actual:
            raise ValueError("build output failed resource round-trip verification")
        from .provenance import build_provenance, write_provenance

        provenance_path = output.with_suffix(output.suffix + ".provenance.json")
        write_provenance(provenance_path, build_provenance(self.workspace_path, output, project_format=self.FORMAT, resources=reopened_entries))
        self.audit.append(
            "project.build",
            outputPath=str(output),
            beforeSha256=_sha256_bytes(self.workspace_path.read_bytes()),
            afterSha256=_sha256_bytes(output.read_bytes()),
            resourceCount=len(reopened_entries),
            verified=True,
            provenancePath=str(provenance_path),
        )
        return output

    def apply_typed_resource(
        self,
        resource_type: str,
        resource_name: str | int,
        language: int | None,
        data: bytes,
        *,
        add: bool = False,
    ) -> Path:
        if self.workspace_path is None or not self.workspace_path.is_file():
            raise ValueError("project has no isolated PE workspace")
        from .pe_writer import LiefPEWriter

        self.outputs_dir.mkdir(parents=True, exist_ok=True)
        candidate = self.outputs_dir / f"{self.workspace_path.stem}.typed-{uuid.uuid4().hex[:8]}{self.workspace_path.suffix}"
        writer = LiefPEWriter()
        if add:
            if not isinstance(resource_name, int) or language is None:
                raise ValueError("typed Add requires integer resource name and language")
            result = writer.add_typed_resource(self.workspace_path, candidate, resource_type, resource_name, language, data)
        else:
            result = writer.replace_typed_resource(self.workspace_path, candidate, resource_type, resource_name, language, data)
        backup = self.workspace_path.with_suffix(self.workspace_path.suffix + ".before-typed.bak")
        shutil.copy2(self.workspace_path, backup)
        _atomic_copy(candidate, self.workspace_path)
        self.entries = {entry.key: entry for entry in _entries_from_lief(writer._parse(self.workspace_path))}
        self.dirty = True
        self.save()
        self.audit.append(
            "project.apply_typed_resource",
            resourceType=resource_type,
            resourceName=resource_name,
            language=language,
            add=add,
            workspacePath=str(self.workspace_path),
            outputPath=str(result.output_path),
            backupPath=str(backup),
            beforeSha256=result.before_sha256,
            afterSha256=_sha256_bytes(self.workspace_path.read_bytes()),
            verified=result.verified,
            verification=result.verification,
            forensicEvidence=result.forensic_evidence,
            forensicBaselinePath=result.forensic_baseline_path,
        )
        return Path(result.output_path)

    def apply_version_info(
        self,
        info: Any,
        resource_name: int | str,
        language: int,
        *,
        codepage: int = 1200,
        add: bool = False,
    ) -> Path:
        from .version_info import VersionInfo

        if not isinstance(info, VersionInfo):
            raise TypeError("info must be a VersionInfo")
        return self.apply_typed_resource("VERSION", resource_name, language, info.to_bytes(codepage), add=add)

    def apply_dialog(
        self,
        dialog: Any,
        resource_name: int | str,
        language: int,
        *,
        add: bool = False,
    ) -> Path:
        from .dialog_resources import DialogResource

        if not isinstance(dialog, DialogResource):
            raise TypeError("dialog must be a DialogResource")
        return self.apply_typed_resource("DIALOG", resource_name, language, dialog.to_bytes(), add=add)

    def apply_res_record(self, record: Any, *, add: bool = False) -> Path:
        if self.workspace_path is None or not self.workspace_path.is_file():
            raise ValueError("project has no isolated PE workspace")
        from .pe_writer import LiefPEWriter
        from .res_format import ResRecord

        if not isinstance(record, ResRecord):
            raise TypeError("record must be a ResRecord")
        self.outputs_dir.mkdir(parents=True, exist_ok=True)
        candidate = self.outputs_dir / f"{self.workspace_path.stem}.res-{uuid.uuid4().hex[:8]}{self.workspace_path.suffix}"
        writer = LiefPEWriter()
        result = writer.add_res_record(self.workspace_path, candidate, record) if add else writer.replace_res_record(self.workspace_path, candidate, record)
        backup = self.workspace_path.with_suffix(self.workspace_path.suffix + ".before-res.bak")
        shutil.copy2(self.workspace_path, backup)
        _atomic_copy(candidate, self.workspace_path)
        self.entries = {entry.key: entry for entry in _entries_from_lief(writer._parse(self.workspace_path))}
        self.dirty = True
        self.save()
        self.audit.append(
            "project.apply_res_record",
            resourceType=record.resource_type,
            resourceName=record.name,
            language=record.language,
            add=add,
            workspacePath=str(self.workspace_path),
            outputPath=str(result.output_path),
            backupPath=str(backup),
            beforeSha256=result.before_sha256,
            afterSha256=_sha256_bytes(self.workspace_path.read_bytes()),
            verified=result.verified,
            verification=result.verification,
            forensicEvidence=result.forensic_evidence,
            forensicBaselinePath=result.forensic_baseline_path,
        )
        return Path(result.output_path)

    def apply_manifest(self, manifest_xml: str) -> Path:
        if self.workspace_path is None or not self.workspace_path.is_file():
            raise ValueError("project has no isolated PE workspace")
        from .pe_writer import LiefPEWriter

        self.outputs_dir.mkdir(parents=True, exist_ok=True)
        candidate = self.outputs_dir / f"{self.workspace_path.stem}.{uuid.uuid4().hex[:8]}{self.workspace_path.suffix}"
        result = LiefPEWriter().replace_manifest(self.workspace_path, candidate, manifest_xml)
        backup = self.workspace_path.with_suffix(self.workspace_path.suffix + ".before-apply.bak")
        shutil.copy2(self.workspace_path, backup)
        _atomic_copy(candidate, self.workspace_path)
        self.entries = {entry.key: entry for entry in _entries_from_lief(LiefPEWriter()._parse(self.workspace_path))}
        self.dirty = True
        self.save()
        self.audit.append(
            "project.apply_manifest",
            workspacePath=str(self.workspace_path),
            outputPath=str(result.output_path),
            backupPath=str(backup),
            beforeSha256=result.before_sha256,
            afterSha256=_sha256_bytes(self.workspace_path.read_bytes()),
            verified=result.verified,
            verification=result.verification,
            forensicEvidence=result.forensic_evidence,
            forensicBaselinePath=result.forensic_baseline_path,
        )
        return Path(result.output_path)

    def save(self) -> None:
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.resources_dir.mkdir(parents=True, exist_ok=True)
        descriptors: list[dict[str, Any]] = []
        for index, entry in enumerate(sorted(self.entries.values(), key=lambda item: item.key)):
            filename = f"{index:05d}-{entry.sha256}.bin"
            target = self.resources_dir / filename
            if not target.exists():
                _atomic_write(target, entry.data)
            descriptors.append(entry.descriptor(f"resources/{filename}"))
        payload = {
            "format": self.FORMAT,
            "original": {"path": self.original_path, "sha256": self.original_sha256},
            "resources": descriptors,
        }
        _atomic_write_text(self.project_file, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        self.dirty = False

    def snapshot(self, label: str) -> Path:
        self.save()
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        safe_label = "".join(character if character.isalnum() or character in "-_" else "_" for character in label)
        target = self.snapshots_dir / f"{safe_label or 'snapshot'}.json"
        _atomic_write_text(target, self.project_file.read_text(encoding="utf-8"))
        if self.workspace_path is not None and self.workspace_path.is_file():
            _atomic_copy(self.workspace_path, _snapshot_workspace_path(target))
        return target

    def restore_snapshot(self, snapshot: str | Path, *, backup_current: bool = True) -> Path:
        if self.workspace_path is None or not self.workspace_path.is_file():
            raise ValueError("project has no isolated PE workspace")
        snapshot_path = Path(snapshot)
        if snapshot_path.suffix != ".json":
            snapshot_path = self.snapshots_dir / f"{snapshot_path.name}.json"
        snapshot_path = snapshot_path.expanduser().resolve()
        snapshots_root = self.snapshots_dir.resolve()
        if snapshot_path.parent != snapshots_root:
            raise ValueError("snapshot must be inside the project snapshots directory")
        if not snapshot_path.is_file():
            raise ValueError(f"snapshot not found: {snapshot_path}")
        workspace_snapshot = _snapshot_workspace_path(snapshot_path)
        if not workspace_snapshot.is_file():
            raise ValueError(f"snapshot workspace not found: {workspace_snapshot}")
        payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
        if payload.get("format") != self.FORMAT:
            raise ValueError("unsupported project snapshot format")
        entries = _entries_from_payload(self.project_dir, payload)
        expected = {(entry.key, entry.sha256) for entry in entries}
        backup: Path | None = None
        if backup_current:
            backup = self.workspace_path.with_suffix(self.workspace_path.suffix + ".before-restore.bak")
            shutil.copy2(self.workspace_path, backup)
        try:
            _atomic_copy(workspace_snapshot, self.workspace_path)
            from .pe_writer import LiefPEWriter

            actual_entries = _entries_from_lief(LiefPEWriter()._parse(self.workspace_path))
            actual = {(entry.key, entry.sha256) for entry in actual_entries}
            if actual != expected:
                raise ValueError("snapshot workspace failed resource verification")
        except Exception:
            if backup is not None and backup.is_file():
                _atomic_copy(backup, self.workspace_path)
            raise
        original = payload.get("original") or {}
        self.original_path = original.get("path")
        self.original_sha256 = original.get("sha256")
        self.entries = {entry.key: entry for entry in entries}
        self.dirty = True
        self.save()
        self.audit.append(
            "project.restore_snapshot",
            snapshotPath=str(snapshot_path),
            workspacePath=str(self.workspace_path),
            backupPath=str(backup) if backup else None,
            resourceCount=len(entries),
            verified=True,
        )
        return self.workspace_path

    @classmethod
    def load(cls, project_dir: Path) -> Project:
        project_dir = Path(project_dir).expanduser().resolve()
        project_file = project_dir / "project.json"
        payload = json.loads(project_file.read_text(encoding="utf-8"))
        if payload.get("format") != cls.FORMAT:
            raise ValueError("unsupported project format")
        original = payload.get("original") or {}
        entries = _entries_from_payload(project_dir, payload)
        return cls(
            project_dir,
            original_path=original.get("path"),
            original_sha256=original.get("sha256"),
            entries=entries,
        )


def _entries_from_payload(project_dir: Path, payload: dict[str, Any]) -> list[ResourceEntry]:
    entries: list[ResourceEntry] = []
    for descriptor in payload.get("resources", []):
        data_path = (project_dir / descriptor["dataFile"]).resolve()
        project_root = project_dir.resolve()
        if data_path != project_root and project_root not in data_path.parents:
            raise ValueError(f"resource data path escapes project directory: {data_path}")
        data = data_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != descriptor["sha256"]:
            raise ValueError(f"resource data hash mismatch: {data_path}")
        entries.append(
            ResourceEntry(
                resource_type=str(descriptor["type"]),
                name=str(descriptor["name"]),
                language=descriptor.get("language"),
                data=data,
                metadata=descriptor.get("metadata") or {},
            )
        )
    return entries


def _snapshot_workspace_path(snapshot_path: Path) -> Path:
    return snapshot_path.with_suffix(snapshot_path.suffix + ".workspace")


def _entries_from_lief(binary: Any) -> list[ResourceEntry]:
    type_names = {
        1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
        7: "FONTDIR", 8: "FONT", 9: "ACCELERATORS", 10: "RCDATA", 11: "MESSAGETABLE",
        12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST",
    }
    if not binary.has_resources:
        return []
    entries: list[ResourceEntry] = []
    for type_node in binary.resources.childs:
        resource_type = type_names.get(int(type_node.id), str(type_node.id))
        for name_node in type_node.childs:
            resource_name = str(name_node.name) if getattr(name_node, "has_name", False) else str(name_node.id)
            for leaf in name_node.childs:
                entries.append(
                    ResourceEntry(
                        resource_type,
                        resource_name,
                        int(leaf.id) if isinstance(leaf.id, int) else None,
                        bytes(leaf.content),
                        {"offset": int(getattr(leaf, "offset", 0)), "codePage": int(getattr(leaf, "code_page", 0))},
                    )
                )
    return entries


def _atomic_copy(source: Path, target: Path) -> None:
    _atomic_write(target, Path(source).read_bytes())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_text(path: Path, text: str) -> None:
    _atomic_write(path, text.encode("utf-8"))

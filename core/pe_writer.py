from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief


TYPE_IDS = {
    "CURSOR": 1,
    "BITMAP": 2,
    "ICON": 3,
    "MENU": 4,
    "DIALOG": 5,
    "STRING": 6,
    "FONTDIR": 7,
    "FONT": 8,
    "ACCELERATORS": 9,
    "RCDATA": 10,
    "MESSAGETABLE": 11,
    "GROUP_CURSOR": 12,
    "GROUP_ICON": 14,
    "VERSION": 16,
    "MANIFEST": 24,
}


@dataclass(frozen=True)
class WriteResult:
    input_path: str
    output_path: str
    backup_path: str | None
    before_sha256: str
    after_sha256: str
    resource_type: str | int
    resource_name: str | int
    language: int | None
    verified: bool
    surgical_change: dict[str, Any] | None = None


class PEWriterError(RuntimeError):
    pass


class LiefPEWriter:
    """Save-As writer backed by LIEF; it refuses in-place writes."""

    def replace_manifest(
        self,
        input_path: Path,
        output_path: Path,
        manifest_xml: str,
        *,
        backup_existing_output: bool = True,
    ) -> WriteResult:
        binary = self._parse(input_path)
        if not binary.has_resources:
            raise PEWriterError("input has no resource directory")
        binary.resources_manager.manifest = manifest_xml
        result = self._write(
            binary,
            input_path,
            output_path,
            resource_type="MANIFEST",
            resource_name=1,
            language=None,
            backup_existing_output=backup_existing_output,
        )
        reopened = self._parse(Path(result.output_path))
        if reopened.resources_manager.manifest != manifest_xml:
            raise PEWriterError("manifest round-trip verification failed")
        return result

    def replace_typed_resource(
        self,
        input_path: Path,
        output_path: Path,
        resource_type: str,
        resource_name: str | int,
        language: int | None,
        data: bytes,
        *,
        backup_existing_output: bool = True,
    ) -> WriteResult:
        canonical = self.validate_resource_payload(resource_type, data)
        return self.replace_resource(input_path, output_path, resource_type, resource_name, language, canonical, backup_existing_output=backup_existing_output)

    @staticmethod
    def validate_resource_payload(resource_type: str, data: bytes) -> bytes:
        resource_type = resource_type.upper()
        if resource_type == "BITMAP":
            from .image_resources import BitmapResource

            return BitmapResource.from_dib(data).to_dib()
        if resource_type in {"GROUP_ICON", "GROUP_CURSOR"}:
            from .image_resources import IconCursorGroup

            group = IconCursorGroup.parse(data)
            if group.kind != ("ICON" if resource_type == "GROUP_ICON" else "CURSOR"):
                raise PEWriterError(f"{resource_type} payload has the wrong group kind")
            return group.to_bytes()
        if resource_type == "MENU":
            from .menu_resources import MenuResource

            return MenuResource.parse(data).to_bytes()
        if resource_type in {"STRING", "STRINGTABLE"}:
            from .string_table import StringTableBlock

            return StringTableBlock.from_bytes(1, data).to_bytes()
        if resource_type == "VERSION":
            from .version_info import VersionInfo

            return VersionInfo.from_bytes(data).to_bytes()
        return bytes(data)

    def replace_res_record(
        self,
        input_path: Path,
        output_path: Path,
        record: Any,
        *,
        backup_existing_output: bool = True,
    ) -> WriteResult:
        from .res_format import ResRecord

        if not isinstance(record, ResRecord):
            raise TypeError("record must be a ResRecord")
        data = record.data
        if isinstance(record.resource_type, str) and record.resource_type.upper() in {"BITMAP", "GROUP_ICON", "GROUP_CURSOR", "MENU", "STRING", "STRINGTABLE"}:
            data = self.validate_resource_payload(record.resource_type, data)
        return self.replace_resource(
            input_path,
            output_path,
            record.resource_type,
            record.name,
            record.language,
            data,
            backup_existing_output=backup_existing_output,
        )

    def add_res_record(
        self,
        input_path: Path,
        output_path: Path,
        record: Any,
        *,
        backup_existing_output: bool = True,
    ) -> WriteResult:
        from .res_format import ResRecord

        if not isinstance(record, ResRecord):
            raise TypeError("record must be a ResRecord")
        data = record.data
        if isinstance(record.resource_type, str) and record.resource_type.upper() in {"BITMAP", "GROUP_ICON", "GROUP_CURSOR", "MENU", "STRING", "STRINGTABLE"}:
            data = self.validate_resource_payload(record.resource_type, data)
        if not isinstance(record.name, int):
            raise PEWriterError("LIEF Add requires numeric resource name")
        return self.add_resource(
            input_path,
            output_path,
            record.resource_type,
            record.name,
            record.language,
            data,
            backup_existing_output=backup_existing_output,
        )

    def plan_replace_resource(
        self,
        input_path: Path,
        resource_type: str | int,
        resource_name: str | int,
        language: int | None,
        data: bytes,
    ) -> dict[str, Any]:
        binary = self._parse(input_path)
        leaf = self._find_resource(binary, resource_type, resource_name, language)
        if leaf is None:
            raise PEWriterError("resource was not found")
        before_data = bytes(leaf.content)
        leaf.content = bytes(data)
        return self._plan(binary, input_path, "replace", resource_type, resource_name, language, len(before_data), len(data))

    def plan_add_resource(
        self,
        input_path: Path,
        resource_type: str | int,
        resource_name: int,
        language: int,
        data: bytes,
    ) -> dict[str, Any]:
        binary = self._parse(input_path)
        if self._find_resource(binary, resource_type, resource_name, language) is not None:
            raise PEWriterError("resource already exists")
        self._add_leaf(binary, resource_type, resource_name, language, data)
        return self._plan(binary, input_path, "add", resource_type, resource_name, language, 0, len(data))

    def replace_resource(
        self,
        input_path: Path,
        output_path: Path,
        resource_type: str | int,
        resource_name: str | int,
        language: int | None,
        data: bytes,
        *,
        backup_existing_output: bool = True,
    ) -> WriteResult:
        binary = self._parse(input_path)
        leaf = self._find_resource(binary, resource_type, resource_name, language)
        if leaf is None:
            raise PEWriterError("resource was not found")
        leaf.content = bytes(data)
        result = self._write(binary, input_path, output_path, resource_type, resource_name, language, backup_existing_output)
        reopened = self._parse(Path(result.output_path))
        verified_leaf = self._find_resource(reopened, resource_type, resource_name, language)
        if verified_leaf is None or bytes(verified_leaf.content) != bytes(data):
            raise PEWriterError("resource round-trip verification failed")
        return result

    def add_typed_resource(
        self,
        input_path: Path,
        output_path: Path,
        resource_type: str,
        resource_name: int,
        language: int,
        data: bytes,
        *,
        backup_existing_output: bool = True,
    ) -> WriteResult:
        canonical = self.validate_resource_payload(resource_type, data)
        return self.add_resource(input_path, output_path, resource_type, resource_name, language, canonical, backup_existing_output=backup_existing_output)

    def add_resource(
        self,
        input_path: Path,
        output_path: Path,
        resource_type: str | int,
        resource_name: str | int,
        language: int,
        data: bytes,
        *,
        backup_existing_output: bool = True,
    ) -> WriteResult:
        binary = self._parse(input_path)
        if self._find_resource(binary, resource_type, resource_name, language) is not None:
            raise PEWriterError("resource already exists")
        self._add_leaf(binary, resource_type, resource_name, language, data)
        result = self._write(binary, input_path, output_path, resource_type, resource_name, language, backup_existing_output)
        reopened = self._parse(Path(result.output_path))
        leaf = self._find_resource(reopened, resource_type, resource_name, language)
        if leaf is None or bytes(leaf.content) != bytes(data):
            raise PEWriterError("added resource round-trip verification failed")
        return result

    def delete_resource(
        self,
        input_path: Path,
        output_path: Path,
        resource_type: str | int,
        resource_name: str | int,
        language: int | None,
        *,
        backup_existing_output: bool = True,
    ) -> WriteResult:
        binary = self._parse(input_path)
        nodes = self._find_nodes(binary, resource_type, resource_name, language)
        if nodes is None:
            raise PEWriterError("resource was not found")
        type_node, name_node, leaf = nodes
        name_node.delete_child(leaf)
        if not name_node.childs:
            type_node.delete_child(name_node)
        if not type_node.childs:
            binary.resources.delete_child(type_node)
        result = self._write(binary, input_path, output_path, resource_type, resource_name, language, backup_existing_output)
        reopened = self._parse(Path(result.output_path))
        if self._find_resource(reopened, resource_type, resource_name, language) is not None:
            raise PEWriterError("deleted resource is still present after round-trip")
        return result

    def change_language(
        self,
        input_path: Path,
        output_path: Path,
        resource_type: str | int,
        resource_name: str | int,
        source_language: int,
        target_language: int,
        *,
        backup_existing_output: bool = True,
    ) -> WriteResult:
        binary = self._parse(input_path)
        source = self._find_resource(binary, resource_type, resource_name, source_language)
        if source is None:
            raise PEWriterError("source language resource was not found")
        source_data = bytes(source.content)
        if self._find_resource(binary, resource_type, resource_name, target_language) is not None:
            raise PEWriterError("target language resource already exists")
        self._add_leaf(binary, resource_type, resource_name, target_language, source_data)
        nodes = self._find_nodes(binary, resource_type, resource_name, source_language)
        assert nodes is not None
        type_node, name_node, leaf = nodes
        name_node.delete_child(leaf)
        result = self._write(binary, input_path, output_path, resource_type, resource_name, target_language, backup_existing_output)
        reopened = self._parse(Path(result.output_path))
        target = self._find_resource(reopened, resource_type, resource_name, target_language)
        old = self._find_resource(reopened, resource_type, resource_name, source_language)
        if target is None or old is not None or bytes(target.content) != source_data:
            raise PEWriterError("language change round-trip verification failed")
        return result

    def _plan(
        self,
        binary: Any,
        input_path: Path,
        operation: str,
        resource_type: str | int,
        resource_name: str | int,
        language: int | None,
        before_size: int,
        after_size: int,
    ) -> dict[str, Any]:
        from .invariants import compare_surgical_change

        input_path = Path(input_path).expanduser().resolve()
        with tempfile.TemporaryDirectory(prefix="resource-studio-plan-") as temporary:
            output = Path(temporary) / input_path.name
            binary.write(str(output))
            report = self.validate_output(output)
            surgical = compare_surgical_change(input_path, output)
            return {
                "operation": operation,
                "inputPath": str(input_path),
                "outputPath": None,
                "resourceType": resource_type,
                "resourceName": resource_name,
                "language": language,
                "beforeSize": before_size,
                "afterSize": after_size,
                "beforeSha256": _sha256(input_path),
                "proposedSha256": _sha256(output),
                "isPE": report.is_pe,
                "warnings": list(report.warnings),
                "surgical": surgical.to_dict(),
                "willWrite": surgical.valid,
            }

    def validate_output(self, output_path: Path):
        from .health import PEHealth

        report = PEHealth.inspect(output_path)
        if not report.is_pe:
            raise PEWriterError("output is not a supported PE binary")
        return report

    def _parse(self, path: Path) -> Any:
        path = Path(path).expanduser().resolve()
        if not path.is_file():
            raise PEWriterError(f"input is not a file: {path}")
        try:
            binary = lief.parse(str(path))
        except Exception as exc:
            raise PEWriterError(f"LIEF could not parse PE: {exc}") from exc
        if binary is None or not isinstance(binary, lief.PE.Binary):
            raise PEWriterError("input is not a supported PE binary")
        return binary

    def _write(
        self,
        binary: Any,
        input_path: Path,
        output_path: Path,
        resource_type: str | int,
        resource_name: str | int,
        language: int | None,
        backup_existing_output: bool,
    ) -> WriteResult:
        input_path = Path(input_path).expanduser().resolve()
        output_path = Path(output_path).expanduser().resolve()
        if input_path == output_path:
            raise PEWriterError("in-place writes are disabled; use Save As")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        backup_path: Path | None = None
        if output_path.exists() and backup_existing_output:
            backup_path = output_path.with_suffix(output_path.suffix + ".bak")
            shutil.copy2(output_path, backup_path)
        from .signature import inspect_signature

        if inspect_signature(input_path).present:
            raise PEWriterError("signed PE modification is blocked; use an explicit strip/re-sign workflow")
        before = _sha256(input_path)
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=output_path.parent, suffix=output_path.suffix, delete=False) as handle:
                temporary = Path(handle.name)
            binary.write(str(temporary))
            os.replace(temporary, output_path)
            temporary = None
            self.validate_output(output_path)
            from .invariants import compare_surgical_change

            surgical = compare_surgical_change(input_path, output_path)
            if not surgical.valid:
                raise PEWriterError("write changed protected PE structures: " + ", ".join(surgical.violations))
        except Exception as exc:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            if backup_path is not None and backup_path.is_file():
                shutil.copy2(backup_path, output_path)
            else:
                output_path.unlink(missing_ok=True)
            raise PEWriterError(f"PE write or output validation failed: {exc}") from exc
        after = _sha256(output_path)
        return WriteResult(
            input_path=str(input_path),
            output_path=str(output_path),
            backup_path=str(backup_path) if backup_path else None,
            before_sha256=before,
            after_sha256=after,
            resource_type=resource_type,
            resource_name=resource_name,
            language=language,
            verified=True,
            surgical_change=surgical.to_dict(),
        )

    @staticmethod
    def _find_nodes(binary: Any, resource_type: str | int, resource_name: str | int, language: int | None) -> tuple[Any, Any, Any] | None:
        if not binary.has_resources:
            return None
        type_value = TYPE_IDS.get(resource_type, resource_type) if isinstance(resource_type, str) else resource_type
        for type_node in binary.resources.childs:
            if not _node_matches(type_node, type_value):
                continue
            for name_node in type_node.childs:
                if not _node_matches(name_node, resource_name):
                    continue
                for leaf in name_node.childs:
                    if language is None or _node_id(leaf) == language:
                        return type_node, name_node, leaf
        return None

    @classmethod
    def _find_resource(cls, binary: Any, resource_type: str | int, resource_name: str | int, language: int | None) -> Any | None:
        nodes = cls._find_nodes(binary, resource_type, resource_name, language)
        return nodes[2] if nodes else None

    @staticmethod
    def _add_leaf(binary: Any, resource_type: str | int, resource_name: str | int, language: int, data: bytes) -> None:
        type_value = TYPE_IDS.get(resource_type, resource_type) if isinstance(resource_type, str) else resource_type
        if not isinstance(type_value, int) or not isinstance(resource_name, int):
            raise PEWriterError("this backend milestone supports numeric resource type/name IDs")
        type_node = next((node for node in binary.resources.childs if _node_matches(node, type_value)), None)
        if type_node is None:
            type_node = binary.resources.add_child(lief.PE.ResourceDirectory(type_value))
        name_node = next((node for node in type_node.childs if _node_matches(node, resource_name)), None)
        if name_node is None:
            name_node = type_node.add_child(lief.PE.ResourceDirectory(resource_name))
        data_node = lief.PE.ResourceData(list(data))
        data_node.id = language
        name_node.add_child(data_node)


def _node_id(node: Any) -> int | None:
    value = getattr(node, "id", None)
    return int(value) if isinstance(value, int) else None


def _node_matches(node: Any, value: str | int) -> bool:
    if isinstance(value, int):
        return _node_id(node) == value
    return str(getattr(node, "name", "")) == value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

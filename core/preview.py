from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .hex_view import HexViewer


@dataclass(frozen=True)
class PreviewResult:
    resource_type: str
    resource_name: str
    language: int | None
    kind: str
    title: str
    summary: dict[str, Any]
    model: dict[str, Any] | None
    raw: dict[str, Any]
    warnings: tuple[str, ...] = ()
    output_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "name": self.resource_name,
            "language": self.language,
            "kind": self.kind,
            "title": self.title,
            "summary": self.summary,
            "model": self.model,
            "raw": self.raw,
            "warnings": list(self.warnings),
            "outputPath": self.output_path,
        }


class PreviewEngine:
    """One read-only preview contract for typed resources with raw fallback."""

    @classmethod
    def preview(
        cls,
        resource_type: str,
        data: bytes,
        *,
        resource_name: str | int = "",
        language: int | None = None,
        raw_length: int = 4096,
        output_path: Path | None = None,
    ) -> PreviewResult:
        resource_type = str(resource_type).upper()
        name = str(resource_name)
        raw = _raw_preview(data, raw_length)
        try:
            if resource_type == "MANIFEST":
                return cls._manifest(resource_type, data, name, language, raw)
            if resource_type == "VERSION":
                return cls._version(resource_type, data, name, language, raw)
            if resource_type == "MENU":
                return cls._menu(resource_type, data, name, language, raw)
            if resource_type == "DIALOG":
                return cls._dialog(resource_type, data, name, language, raw)
            if resource_type in {"STRING", "STRINGTABLE"}:
                return cls._string(resource_type, data, name, language, raw)
            if resource_type == "BITMAP":
                return cls._bitmap(resource_type, data, name, language, raw, output_path)
            if resource_type in {"GROUP_ICON", "GROUP_CURSOR"}:
                return cls._image_group(resource_type, data, name, language, raw)
        except Exception as exc:
            return PreviewResult(resource_type, name, language, "raw", f"Raw {resource_type} preview", {"size": len(data)}, None, raw, (f"typed preview unavailable: {exc}",))
        return PreviewResult(resource_type, name, language, "raw", f"Raw {resource_type} preview", {"size": len(data)}, None, raw)

    @staticmethod
    def _manifest(resource_type: str, data: bytes, name: str, language: int | None, raw: dict[str, Any]) -> PreviewResult:
        from .manifest import ManifestDocument

        document = ManifestDocument.parse(data.decode("utf-8-sig"))
        report = document.validate()
        return PreviewResult(resource_type, name, language, "xml", "Manifest", {"valid": report["valid"], "errors": report["errors"], "warnings": report["warnings"]}, {"format": "resource_studio.manifest.v1", "xml": document.to_xml(), "validation": report}, raw, tuple(report["warnings"]))

    @staticmethod
    def _version(resource_type: str, data: bytes, name: str, language: int | None, raw: dict[str, Any]) -> PreviewResult:
        from .version_info import VersionInfo

        info = VersionInfo.from_bytes(data)
        report = info.validate()
        return PreviewResult(resource_type, name, language, "version-info", "Version Information", {"fileVersion": info.file_version, "productVersion": info.product_version, "stringCount": len(info.strings), "valid": report["valid"]}, json.loads(info.to_json()), raw, tuple(report["warnings"]))

    @staticmethod
    def _menu(resource_type: str, data: bytes, name: str, language: int | None, raw: dict[str, Any]) -> PreviewResult:
        from .menu_resources import MenuResource

        menu = MenuResource.parse(data)
        count = _count_menu_items(menu.items)
        return PreviewResult(resource_type, name, language, "menu-tree", "Menu", {"itemCount": count, "topLevelCount": len(menu.items)}, menu.to_dict(), raw)

    @staticmethod
    def _dialog(resource_type: str, data: bytes, name: str, language: int | None, raw: dict[str, Any]) -> PreviewResult:
        from .dialog_resources import DialogResource

        dialog = DialogResource.parse(data)
        model = dialog.to_dict()
        return PreviewResult(resource_type, name, language, "dialog", "Dialog", {"title": dialog.title, "controlCount": len(dialog.controls), "extended": dialog.extended}, model, raw)

    @staticmethod
    def _string(resource_type: str, data: bytes, name: str, language: int | None, raw: dict[str, Any]) -> PreviewResult:
        from .string_table import StringTableBlock

        block = StringTableBlock.from_bytes(int(name), data)
        model = {"format": "resource_studio.string_table.v1", "blockId": block.block_id, "firstStringId": block.first_string_id, "strings": list(block.strings)}
        return PreviewResult(resource_type, name, language, "string-table", "String Table", {"blockId": block.block_id, "firstStringId": block.first_string_id, "nonEmptyCount": sum(bool(value) for value in block.strings)}, model, raw)

    @staticmethod
    def _bitmap(resource_type: str, data: bytes, name: str, language: int | None, raw: dict[str, Any], output_path: Path | None) -> PreviewResult:
        from .image_resources import BitmapResource

        bitmap = BitmapResource.from_dib(data)
        output = None
        if output_path is not None:
            output_path = Path(output_path).expanduser().resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(bitmap.to_bmp())
            output = str(output_path)
        return PreviewResult(resource_type, name, language, "bitmap", "Bitmap", {"width": bitmap.width, "height": bitmap.height, "bitCount": bitmap.bit_count, "compression": bitmap.compression}, {"format": "resource_studio.bitmap.v1", "width": bitmap.width, "height": bitmap.height, "bitCount": bitmap.bit_count, "outputPath": output}, raw, output_path=output)

    @staticmethod
    def _image_group(resource_type: str, data: bytes, name: str, language: int | None, raw: dict[str, Any]) -> PreviewResult:
        from .image_resources import IconCursorGroup

        group = IconCursorGroup.parse(data)
        return PreviewResult(resource_type, name, language, "image-group", group.kind, {"entryCount": len(group.entries), "dimensions": group.dimensions()}, group.to_dict(), raw)


def _raw_preview(data: bytes, length: int) -> dict[str, Any]:
    if length < 0:
        raise ValueError("raw preview length must be non-negative")
    chunk = HexViewer(data).slice(0, length)
    return {"size": len(data), "shown": len(chunk.data), "hex": chunk.hex(), "ascii": chunk.ascii(), "base64": base64.b64encode(chunk.data).decode("ascii")}


def _count_menu_items(items: list[Any]) -> int:
    return sum(1 + _count_menu_items(item.children) for item in items)

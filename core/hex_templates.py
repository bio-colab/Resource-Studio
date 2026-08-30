from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_SCHEMA = "resource_studio.hex_template.v1"


@dataclass(frozen=True)
class HexField:
    name: str
    offset: int
    length: int
    value: Any
    description: str = ""

    def to_dict(self, data: bytes) -> dict[str, Any]:
        chunk = data[self.offset : self.offset + self.length]
        return {
            "name": self.name,
            "offset": self.offset,
            "length": self.length,
            "value": self.value,
            "hex": chunk.hex(" "),
            "description": self.description,
        }


def build_hex_template(resource_type: str, data: bytes) -> dict[str, Any]:
    """Return bounded structural fields for a resource payload.

    This is a read-only display contract. Unsupported or truncated payloads return
    an explicit empty field list instead of guessing offsets.
    """

    kind = str(resource_type).upper()
    payload = bytes(data)
    fields: list[HexField] = []
    warnings: list[str] = []
    if kind in {"BITMAP", "ICON", "CURSOR"}:
        fields = _bitmap_fields(payload)
        template_name = "BITMAPINFOHEADER"
    elif kind in {"VERSION", "VERSIONINFO"}:
        fields = _version_fields(payload)
        template_name = "VS_VERSIONINFO"
    elif kind in {"MENU", "MENUEX"}:
        fields = _menu_fields(payload)
        template_name = "MENU_HEADER"
    elif kind in {"DIALOG", "DIALOGEX"}:
        fields = _dialog_fields(payload)
        template_name = "DIALOG_HEADER"
    else:
        template_name = "RAW"
        warnings.append(f"no structural template for {kind}")
    if not fields and payload:
        warnings.append("payload is shorter than the known header or has an unsupported layout")
    return {
        "schema": _SCHEMA,
        "resourceType": kind,
        "template": template_name,
        "dataSize": len(payload),
        "fields": [field.to_dict(payload) for field in fields],
        "warnings": warnings,
    }


def _bitmap_fields(data: bytes) -> list[HexField]:
    if len(data) < 40:
        return []
    specs = (
        ("biSize", 0, 4, "uint32", False),
        ("biWidth", 4, 4, "int32", True),
        ("biHeight", 8, 4, "int32", True),
        ("biPlanes", 12, 2, "uint16", False),
        ("biBitCount", 14, 2, "uint16", False),
        ("biCompression", 16, 4, "uint32", False),
        ("biSizeImage", 20, 4, "uint32", False),
        ("biXPelsPerMeter", 24, 4, "int32", True),
        ("biYPelsPerMeter", 28, 4, "int32", True),
        ("biClrUsed", 32, 4, "uint32", False),
        ("biClrImportant", 36, 4, "uint32", False),
    )
    return [HexField(name, offset, length, int.from_bytes(data[offset : offset + length], "little", signed=signed), kind) for name, offset, length, kind, signed in specs]


def _version_fields(data: bytes) -> list[HexField]:
    if len(data) < 6:
        return []
    length = _u16(data, 0)
    value_length = _u16(data, 2)
    fields = [
        HexField("wLength", 0, 2, length, "uint16"),
        HexField("wValueLength", 2, 2, value_length, "uint16"),
        HexField("wType", 4, 2, _u16(data, 4), "uint16; 1 means text, 0 means binary"),
    ]
    key_start = 6
    key_end = key_start
    while key_end + 1 < len(data) and data[key_end : key_end + 2] != b"\x00\x00":
        key_end += 2
    if key_end + 1 < len(data):
        key_length = key_end + 2 - key_start
        key = data[key_start:key_end].decode("utf-16le", errors="replace")
        fields.append(HexField("key", key_start, key_length, key, "UTF-16LE, null terminated"))
        value_offset = (key_end + 2 + 3) & ~3
        value_length_bytes = value_length * 2 if _u16(data, 4) == 1 else value_length
        if value_length_bytes and value_offset + value_length_bytes <= len(data):
            value = data[value_offset : value_offset + value_length_bytes]
            fields.append(HexField("value", value_offset, value_length_bytes, value.decode("utf-16le", errors="replace").rstrip("\x00") if _u16(data, 4) == 1 else value.hex(" "), "aligned value"))
    return fields


def _menu_fields(data: bytes) -> list[HexField]:
    if len(data) < 4:
        return []
    return [HexField("wVersion", 0, 2, _u16(data, 0), "uint16"), HexField("cbHeader", 2, 2, _u16(data, 2), "uint16")]


def _dialog_fields(data: bytes) -> list[HexField]:
    if len(data) < 18:
        return []
    if len(data) >= 26 and _u16(data, 2) == 0xFFFF:
        specs = (("dlgVer", 0, 2, False), ("signature", 2, 2, False), ("helpID", 4, 4, False), ("exStyle", 8, 4, False), ("style", 12, 4, False), ("cDlgItems", 16, 2, False), ("x", 18, 2, True), ("y", 20, 2, True), ("cx", 22, 2, True), ("cy", 24, 2, True))
    else:
        specs = (("style", 0, 4, False), ("exStyle", 4, 4, False), ("cDlgItems", 8, 2, False), ("x", 10, 2, True), ("y", 12, 2, True), ("cx", 14, 2, True), ("cy", 16, 2, True))
    return [HexField(name, offset, length, int.from_bytes(data[offset : offset + length], "little", signed=signed), "dialog header") for name, offset, length, signed in specs]


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


__all__ = ["HexField", "build_hex_template"]

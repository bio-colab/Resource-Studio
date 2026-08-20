from __future__ import annotations

import io
import struct
from dataclasses import dataclass


class ImageResourceError(ValueError):
    pass


@dataclass(frozen=True)
class BitmapResource:
    dib: bytes
    width: int
    height: int
    bit_count: int
    compression: int
    _bmp_pixel_offset: int | None = None

    @classmethod
    def from_dib(cls, data: bytes) -> BitmapResource:
        width, height, bit_count, compression = _dib_fields(data)
        return cls(bytes(data), width, height, bit_count, compression)

    @classmethod
    def from_bmp(cls, data: bytes) -> BitmapResource:
        if len(data) < 14 or data[:2] != b"BM":
            raise ImageResourceError("BMP file must start with BM")
        file_size, _, _, pixel_offset = struct.unpack_from("<IHHI", data, 2)
        if file_size and file_size > len(data):
            raise ImageResourceError("BMP file size exceeds input")
        if pixel_offset < 14 or pixel_offset > len(data):
            raise ImageResourceError("BMP pixel offset is outside input")
        dib = bytes(data[14:])
        width, height, bit_count, compression = _dib_fields(dib)
        return cls(dib, width, height, bit_count, compression, pixel_offset)

    def to_dib(self) -> bytes:
        return bytes(self.dib)

    def to_bmp(self) -> bytes:
        pixel_offset = self._bmp_pixel_offset or _default_bmp_pixel_offset(self.dib, self.bit_count, self.compression)
        if pixel_offset < 14 or pixel_offset > 14 + len(self.dib):
            raise ImageResourceError("BMP pixel offset cannot be represented")
        file_size = 14 + len(self.dib)
        header = b"BM" + struct.pack("<IHHI", file_size, 0, 0, pixel_offset)
        return header + self.dib


def _dib_fields(data: bytes) -> tuple[int, int, int, int]:
    if len(data) < 40:
        raise ImageResourceError("DIB requires a BITMAPINFOHEADER")
    header_size, width, height, planes, bit_count, compression, _, _, _, _, _ = struct.unpack_from("<IiiHHIIiiII", data, 0)
    if header_size < 40 or header_size > len(data):
        raise ImageResourceError("unsupported DIB header size")
    if width <= 0 or height == 0 or planes != 1:
        raise ImageResourceError("invalid DIB dimensions or planes")
    if bit_count not in {1, 4, 8, 16, 24, 32}:
        raise ImageResourceError("unsupported DIB bit depth")
    return width, height, bit_count, compression


def _default_bmp_pixel_offset(dib: bytes, bit_count: int, compression: int) -> int:
    header_size = struct.unpack_from("<I", dib, 0)[0]
    colors_used = struct.unpack_from("<I", dib, 32)[0] if header_size >= 40 else 0
    palette = (colors_used or (1 << bit_count)) * 4 if bit_count <= 8 else 0
    masks = 12 if compression == 3 else 16 if compression == 6 else 0
    return 14 + header_size + masks + palette


@dataclass(frozen=True)
class IconCursorEntry:
    width: int
    height: int
    color_count: int
    planes_or_hotspot_x: int
    bit_count_or_hotspot_y: int
    bytes_in_resource: int
    resource_id: int

    def to_dict(self) -> dict[str, int]:
        return {"width": self.width, "height": self.height, "colorCount": self.color_count, "planesOrHotspotX": self.planes_or_hotspot_x, "bitCountOrHotspotY": self.bit_count_or_hotspot_y, "bytesInResource": self.bytes_in_resource, "resourceId": self.resource_id}

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "IconCursorEntry":
        return cls(int(payload["width"]), int(payload["height"]), int(payload.get("colorCount", 0)), int(payload.get("planesOrHotspotX", 0)), int(payload.get("bitCountOrHotspotY", 0)), int(payload["bytesInResource"]), int(payload["resourceId"]))

    def to_bytes(self) -> bytes:
        if not 0 <= self.width <= 255 or not 0 <= self.height <= 255:
            raise ImageResourceError("icon/cursor dimensions must fit BYTE")
        if not 0 <= self.resource_id <= 0xFFFF:
            raise ImageResourceError("icon/cursor resource id must fit WORD")
        return struct.pack(
            "<BBBBHHIH",
            self.width,
            self.height,
            self.color_count,
            0,
            self.planes_or_hotspot_x,
            self.bit_count_or_hotspot_y,
            self.bytes_in_resource,
            self.resource_id,
        )


def _png_to_bmp(data: bytes) -> bytes:
    try:
        from PIL import Image
    except ImportError as exc:
        raise ImageResourceError("PNG icon/cursor payload conversion requires Pillow") from exc
    try:
        with Image.open(io.BytesIO(data)) as image:
            output = io.BytesIO()
            image.convert("RGBA").save(output, format="BMP")
            return output.getvalue()
    except Exception as exc:
        raise ImageResourceError(f"invalid PNG image payload: {exc}") from exc


def _icon_dib_to_bmp(data: bytes) -> bytes:
    if len(data) < 40:
        raise ImageResourceError("icon/cursor payload requires a BITMAPINFOHEADER")
    header_size, width, dib_height, planes, bit_count, compression, _, _, _, _, _ = struct.unpack_from("<IiiHHIIiiII", data, 0)
    if dib_height == 0 or dib_height % 2 != 0 or width <= 0 or planes != 1:
        raise ImageResourceError("invalid icon/cursor DIB dimensions")
    pixel_offset = _default_bmp_pixel_offset(data, bit_count, compression) - 14
    if pixel_offset < header_size or pixel_offset > len(data):
        raise ImageResourceError("icon/cursor DIB pixel offset is outside payload")
    actual_height = abs(dib_height) // 2
    row_stride = ((width * bit_count + 31) // 32) * 4
    xor_size = row_stride * actual_height
    if pixel_offset + xor_size > len(data):
        raise ImageResourceError("icon/cursor XOR bitmap is truncated")
    dib = bytearray(data[:pixel_offset + xor_size])
    struct.pack_into("<i", dib, 8, actual_height if dib_height > 0 else -actual_height)
    file_size = 14 + len(dib)
    return b"BM" + struct.pack("<IHHI", file_size, 0, 0, 14 + pixel_offset) + bytes(dib)


def icon_cursor_payload_to_bmp(data: bytes, kind: str) -> bytes:
    """Convert one ICON/CURSOR resource payload to a viewable BMP."""
    if kind.upper() not in {"ICON", "CURSOR"}:
        raise ImageResourceError("kind must be ICON or CURSOR")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return _png_to_bmp(data)
    return _icon_dib_to_bmp(data)


def _bmp_to_icon_dib(data: bytes) -> bytes:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        data = _png_to_bmp(data)
    bitmap = BitmapResource.from_bmp(data)
    dib = bytearray(bitmap.to_dib())
    height = struct.unpack_from("<i", dib, 8)[0]
    if height == 0:
        raise ImageResourceError("BMP height cannot be zero")
    struct.pack_into("<i", dib, 8, height * 2)
    mask_stride = ((bitmap.width + 31) // 32) * 4
    return bytes(dib) + bytes(mask_stride * abs(height))


def icon_cursor_bmp_to_payload(data: bytes, kind: str) -> bytes:
    """Convert a BMP image to one ICON/CURSOR DIB payload."""
    if kind.upper() not in {"ICON", "CURSOR"}:
        raise ImageResourceError("kind must be ICON or CURSOR")
    return _bmp_to_icon_dib(data)


@dataclass(frozen=True)
class IconCursorGroup:
    kind: str
    entries: tuple[IconCursorEntry, ...]

    @classmethod
    def parse(cls, data: bytes) -> IconCursorGroup:
        if len(data) < 6:
            raise ImageResourceError("icon/cursor group is truncated")
        reserved, kind_id, count = struct.unpack_from("<HHH", data, 0)
        if reserved != 0 or kind_id not in {1, 2} or count == 0:
            raise ImageResourceError("invalid icon/cursor group header")
        expected = 6 + 14 * count
        if len(data) != expected:
            raise ImageResourceError("icon/cursor group has unexpected length")
        entries: list[IconCursorEntry] = []
        for offset in range(6, expected, 14):
            width, height, color_count, reserved_entry, first, second, size, resource_id = struct.unpack_from("<BBBBHHIH", data, offset)
            if reserved_entry != 0 or size == 0:
                raise ImageResourceError("invalid icon/cursor group entry")
            entries.append(IconCursorEntry(width, height, color_count, first, second, size, resource_id))
        return cls("ICON" if kind_id == 1 else "CURSOR", tuple(entries))

    def to_dict(self) -> dict[str, object]:
        return {"format": "resource_studio.image_group.v1", "kind": self.kind, "entries": [entry.to_dict() for entry in self.entries]}

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "IconCursorGroup":
        if payload.get("format") != "resource_studio.image_group.v1":
            raise ImageResourceError("unsupported image group model format")
        entries = payload.get("entries")
        if not isinstance(entries, list) or not entries:
            raise ImageResourceError("image group requires entries")
        return cls(str(payload["kind"]), tuple(IconCursorEntry.from_dict(entry) for entry in entries))

    def to_bytes(self) -> bytes:
        kind_id = {"ICON": 1, "CURSOR": 2}.get(self.kind.upper())
        if kind_id is None or not self.entries:
            raise ImageResourceError("group kind must be ICON or CURSOR with entries")
        return struct.pack("<HHH", 0, kind_id, len(self.entries)) + b"".join(entry.to_bytes() for entry in self.entries)

    def dimensions(self) -> tuple[tuple[int, int], ...]:
        return tuple((entry.width or 256, entry.height or 256) for entry in self.entries)

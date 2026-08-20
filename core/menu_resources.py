from __future__ import annotations

import struct
from dataclasses import dataclass, field


class MenuResourceError(ValueError):
    pass


MF_POPUP = 0x0010
MF_SEPARATOR = 0x0800
MF_END = 0x0080


@dataclass
class MenuItem:
    item_id: int
    text: str
    flags: int = 0
    children: list[MenuItem] = field(default_factory=list)

    @property
    def is_popup(self) -> bool:
        return bool(self.flags & MF_POPUP) or bool(self.children)

    @property
    def is_separator(self) -> bool:
        return bool(self.flags & MF_SEPARATOR)


@dataclass
class MenuResource:
    items: list[MenuItem]
    version: int = 0
    header_size: int = 4

    @classmethod
    def parse(cls, data: bytes) -> MenuResource:
        if len(data) < 4:
            raise MenuResourceError("menu resource header is truncated")
        version, header_size = struct.unpack_from("<HH", data, 0)
        if version != 0 or header_size < 4 or header_size > len(data):
            raise MenuResourceError("unsupported menu resource header")
        items, offset = _parse_level(data, header_size)
        if offset != len(data):
            raise MenuResourceError("trailing bytes after menu resource")
        return cls(items, version, header_size)

    def to_bytes(self) -> bytes:
        if self.version != 0 or self.header_size != 4:
            raise MenuResourceError("only standard version-0 menus are supported")
        if not self.items:
            raise MenuResourceError("menu must contain at least one item")
        return struct.pack("<HH", self.version, self.header_size) + _encode_level(self.items)

    def find_id(self, item_id: int) -> MenuItem | None:
        for item in self.items:
            if item.item_id == item_id:
                return item
            nested = MenuResource(item.children).find_id(item_id) if item.children else None
            if nested is not None:
                return nested
        return None


def _parse_level(data: bytes, offset: int) -> tuple[list[MenuItem], int]:
    items: list[MenuItem] = []
    while True:
        if offset + 10 > len(data):
            raise MenuResourceError("menu item header is truncated")
        options, item_id = struct.unpack_from("<II", data, offset)
        offset += 8
        text, offset = _read_wstring(data, offset)
        children: list[MenuItem] = []
        if options & MF_POPUP:
            children, offset = _parse_level(data, offset)
        item = MenuItem(item_id, text, options & ~MF_END, children)
        items.append(item)
        if options & MF_END:
            return items, offset


def _encode_level(items: list[MenuItem]) -> bytes:
    output = bytearray()
    for index, item in enumerate(items):
        if not 0 <= item.item_id <= 0xFFFFFFFF:
            raise MenuResourceError("menu item ID must fit DWORD")
        options = item.flags | (MF_POPUP if item.children else 0)
        if index == len(items) - 1:
            options |= MF_END
        output.extend(struct.pack("<II", options, item.item_id))
        output.extend(item.text.encode("utf-16le"))
        output.extend(b"\x00\x00")
        if item.children:
            output.extend(_encode_level(item.children))
    return bytes(output)


def _read_wstring(data: bytes, offset: int) -> tuple[str, int]:
    end = offset
    while end + 2 <= len(data):
        if data[end : end + 2] == b"\x00\x00":
            try:
                return data[offset:end].decode("utf-16le"), end + 2
            except UnicodeDecodeError as exc:
                raise MenuResourceError("menu text is not valid UTF-16LE") from exc
        end += 2
    raise MenuResourceError("menu text is not null terminated")

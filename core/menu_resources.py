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

    def to_dict(self) -> dict[str, object]:
        return {"id": self.item_id, "text": self.text, "flags": self.flags, "children": [child.to_dict() for child in self.children]}

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "MenuItem":
        if not isinstance(payload, dict):
            raise MenuResourceError("menu item must be an object")
        children = payload.get("children", [])
        if not isinstance(children, list):
            raise MenuResourceError("menu item children must be a list")
        return cls(int(payload.get("id", 0)), str(payload.get("text", "")), int(payload.get("flags", 0)), [cls.from_dict(child) for child in children])

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

    def to_dict(self) -> dict[str, object]:
        return {"format": "resource_studio.menu.v1", "version": self.version, "headerSize": self.header_size, "items": [item.to_dict() for item in self.items]}

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "MenuResource":
        if payload.get("format") != "resource_studio.menu.v1":
            raise MenuResourceError("unsupported menu model format")
        items = payload.get("items")
        if not isinstance(items, list) or not items:
            raise MenuResourceError("menu model must contain items")
        return cls([MenuItem.from_dict(item) for item in items], int(payload.get("version", 0)), int(payload.get("headerSize", 4)))

    def find_id(self, item_id: int) -> MenuItem | None:
        for item in self.items:
            if item.item_id == item_id:
                return item
            nested = MenuResource(item.children).find_id(item_id) if item.children else None
            if nested is not None:
                return nested
        return None

    def move_item(self, item_id: int, new_parent_id: int | None, index: int) -> None:
        """Move one node within the menu tree without changing its identity."""
        if item_id == new_parent_id:
            raise MenuResourceError("a menu item cannot be its own parent")
        item = _detach_item(self.items, item_id)
        if item is None:
            raise MenuResourceError(f"menu item not found: {item_id}")
        if new_parent_id is None:
            target = self.items
        else:
            parent = self.find_id(new_parent_id)
            if parent is None:
                raise MenuResourceError(f"menu parent not found: {new_parent_id}")
            if _contains_item(item, new_parent_id):
                _restore_item(self.items, item)
                raise MenuResourceError("cannot move a menu item below its descendant")
            parent.flags |= MF_POPUP
            target = parent.children
        if index < 0 or index > len(target):
            raise MenuResourceError("menu insertion index is outside the target list")
        target.insert(index, item)

    def update_item(self, item_id: int, *, text: str | None = None, flags: int | None = None) -> None:
        item = self.find_id(item_id)
        if item is None:
            raise MenuResourceError(f"menu item not found: {item_id}")
        if text is not None:
            item.text = text
        if flags is not None:
            item.flags = flags


def _detach_item(items: list[MenuItem], item_id: int) -> MenuItem | None:
    for position, item in enumerate(items):
        if item.item_id == item_id:
            return items.pop(position)
        detached = _detach_item(item.children, item_id)
        if detached is not None:
            return detached
    return None


def _restore_item(items: list[MenuItem], item: MenuItem) -> None:
    items.append(item)


def _contains_item(item: MenuItem, item_id: int) -> bool:
    return item.item_id == item_id or any(_contains_item(child, item_id) for child in item.children)


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

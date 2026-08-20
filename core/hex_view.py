from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass(frozen=True)
class HexSlice:
    offset: int
    data: bytes

    def hex(self) -> str:
        return self.data.hex(" ")

    def ascii(self) -> str:
        return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in self.data)

    def as_c_array(self) -> str:
        return ", ".join(f"0x{byte:02X}" for byte in self.data)

    def base64(self) -> str:
        return base64.b64encode(self.data).decode("ascii")


class HexViewer:
    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)

    def slice(self, offset: int = 0, length: int = 256) -> HexSlice:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if offset > len(self._data):
            raise ValueError("offset is outside the data")
        return HexSlice(offset, self._data[offset : offset + length])

    def find(self, needle: bytes, start: int = 0) -> int:
        if not needle:
            raise ValueError("needle cannot be empty")
        if start < 0:
            raise ValueError("start must be non-negative")
        return self._data.find(needle, start)

    def resource_slice(self, index: object, resource_type: str, name: str, language: int | None, length: int = 256) -> HexSlice:
        """Return a raw-file slice using a ResourceIndex-like object."""
        item = index.find(resource_type, name, language)
        if item is None:
            raise KeyError(f"resource not found: {(resource_type, name, language)}")
        offset = getattr(item, "offset", None)
        if not isinstance(offset, int) or offset < 0:
            raise ValueError("resource has no valid file offset")
        return self.slice(offset, length)

    @property
    def size(self) -> int:
        return len(self._data)

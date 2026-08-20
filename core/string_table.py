from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class StringTableBlock:
    block_id: int
    strings: tuple[str, ...]

    SLOT_COUNT = 16

    def __post_init__(self) -> None:
        if not 1 <= self.block_id <= 0xFFFF:
            raise ValueError("STRINGTABLE block_id must fit WORD")
        if len(self.strings) != self.SLOT_COUNT:
            raise ValueError("STRINGTABLE blocks must contain exactly 16 slots")
        for value in self.strings:
            if "\x00" in value:
                raise ValueError("STRINGTABLE strings cannot contain NUL")
            if len(value) > 0xFFFF:
                raise ValueError("STRINGTABLE string is too long")

    @property
    def first_string_id(self) -> int:
        return (self.block_id - 1) * self.SLOT_COUNT + 1

    def to_bytes(self) -> bytes:
        payload = bytearray()
        for value in self.strings:
            encoded = value.encode("utf-16le")
            payload.extend(struct.pack("<H", len(value)))
            payload.extend(encoded)
        return bytes(payload)

    @classmethod
    def from_bytes(cls, block_id: int, data: bytes) -> StringTableBlock:
        offset = 0
        values: list[str] = []
        for _ in range(cls.SLOT_COUNT):
            if offset + 2 > len(data):
                raise ValueError("truncated STRINGTABLE length")
            length = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            byte_count = length * 2
            if offset + byte_count > len(data):
                raise ValueError("truncated STRINGTABLE text")
            try:
                values.append(data[offset : offset + byte_count].decode("utf-16le"))
            except UnicodeDecodeError as exc:
                raise ValueError("invalid STRINGTABLE UTF-16 text") from exc
            offset += byte_count
        if offset != len(data):
            raise ValueError("STRINGTABLE has trailing bytes")
        return cls(block_id, tuple(values))

    def get(self, string_id: int) -> str:
        index = string_id - self.first_string_id
        if not 0 <= index < self.SLOT_COUNT:
            raise KeyError(f"string id outside block: {string_id}")
        return self.strings[index]


def string_table_block_id(string_id: int) -> int:
    if not 1 <= string_id <= 0xFFFF:
        raise ValueError("string_id must fit WORD")
    return ((string_id - 1) // StringTableBlock.SLOT_COUNT) + 1

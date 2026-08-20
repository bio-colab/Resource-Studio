from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Union

ResId = Union[int, str]


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _encode_id(value: ResId) -> bytes:
    if isinstance(value, int):
        if not 1 <= value <= 0xFFFF:
            raise ValueError("numeric RES identifiers must fit WORD and be non-zero")
        return struct.pack("<HH", 0xFFFF, value)
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("RES identifiers must be numeric or NUL-free text")
    return value.encode("utf-16le") + b"\x00\x00"


def _decode_id(data: bytes, offset: int) -> tuple[ResId, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated RES identifier")
    marker = struct.unpack_from("<H", data, offset)[0]
    if marker == 0xFFFF:
        if offset + 4 > len(data):
            raise ValueError("truncated numeric RES identifier")
        return struct.unpack_from("<H", data, offset + 2)[0], offset + 4
    start = offset
    cursor = offset
    while True:
        if cursor + 2 > len(data):
            raise ValueError("unterminated RES text identifier")
        code_unit = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        if code_unit == 0:
            break
    try:
        value = data[start : cursor - 2].decode("utf-16le")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid RES UTF-16 identifier") from exc
    return value, cursor


@dataclass(frozen=True)
class ResRecord:
    resource_type: ResId
    name: ResId
    language: int
    data: bytes
    data_version: int = 0
    memory_flags: int = 0
    version: int = 0
    characteristics: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.language <= 0xFFFF:
            raise ValueError("RES language must fit WORD")
        if not 0 <= self.data_version <= 0xFFFFFFFF:
            raise ValueError("RES data_version must fit DWORD")
        if not 0 <= self.memory_flags <= 0xFFFF:
            raise ValueError("RES memory_flags must fit WORD")
        if not 0 <= self.version <= 0xFFFFFFFF:
            raise ValueError("RES version must fit DWORD")
        if not 0 <= self.characteristics <= 0xFFFFFFFF:
            raise ValueError("RES characteristics must fit DWORD")
        if not isinstance(self.data, (bytes, bytearray, memoryview)):
            raise TypeError("RES data must be bytes-like")

    def to_bytes(self) -> bytes:
        header = _encode_id(self.resource_type) + _encode_id(self.name)
        header += b"\x00" * ((_align4(8 + len(header)) - 8) - len(header))
        header += struct.pack(
            "<IHHII",
            self.data_version,
            self.memory_flags,
            self.language,
            self.version,
            self.characteristics,
        )
        header_size = 8 + len(header)
        data = bytes(self.data)
        record = struct.pack("<II", len(data), header_size) + header + data
        return record + b"\x00" * (_align4(len(record)) - len(record))


@dataclass
class ResFile:
    records: list[ResRecord] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return b"".join(record.to_bytes() for record in self.records)

    @classmethod
    def from_bytes(cls, data: bytes) -> ResFile:
        payload = bytes(data)
        records: list[ResRecord] = []
        offset = 0
        while offset < len(payload):
            if len(payload) - offset < 8:
                raise ValueError("truncated RES record header")
            data_size, header_size = struct.unpack_from("<II", payload, offset)
            if header_size < 24 or header_size % 4:
                raise ValueError("invalid RES header size")
            header_end = offset + header_size
            data_end = header_end + data_size
            record_end = _align4(data_end)
            if header_end > len(payload) or data_end > len(payload):
                raise ValueError("truncated RES record")
            cursor = offset + 8
            resource_type, cursor = _decode_id(payload, cursor)
            name, cursor = _decode_id(payload, cursor)
            cursor = _align4(cursor)
            if cursor + 16 > header_end:
                raise ValueError("RES fixed header exceeds header size")
            data_version, memory_flags, language, version, characteristics = struct.unpack_from("<IHHII", payload, cursor)
            if cursor + 16 != header_end:
                raise ValueError("RES header contains unexpected bytes")
            records.append(
                ResRecord(
                    resource_type,
                    name,
                    language,
                    payload[header_end:data_end],
                    data_version,
                    memory_flags,
                    version,
                    characteristics,
                )
            )
            offset = record_end
        return cls(records)

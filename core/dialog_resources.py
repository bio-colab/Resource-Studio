from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


class DialogResourceError(ValueError):
    pass


DS_SETFONT = 0x00000040
DIALOGEX_SIGNATURE = 0xFFFF

STANDARD_CONTROL_CLASSES = {
    0x0080: "BUTTON",
    0x0081: "EDIT",
    0x0082: "STATIC",
    0x0083: "LISTBOX",
    0x0084: "SCROLLBAR",
    0x0085: "COMBOBOX",
}


@dataclass
class DialogControl:
    control_id: int
    x: int
    y: int
    width: int
    height: int
    style: int = 0
    exstyle: int = 0
    class_name: int | str = ""
    title: int | str = ""
    creation_data: bytes = b""
    help_id: int = 0

    @property
    def class_label(self) -> str:
        if isinstance(self.class_name, int):
            return STANDARD_CONTROL_CLASSES.get(self.class_name, f"ORDINAL(0x{self.class_name:04X})")
        return str(self.class_name) or "CUSTOM"

    def to_dict(self) -> dict[str, Any]:
        return {"controlId": self.control_id, "x": self.x, "y": self.y, "width": self.width, "height": self.height, "style": self.style, "exstyle": self.exstyle, "class": self.class_name, "title": self.title, "creationDataHex": self.creation_data.hex(), "helpId": self.help_id}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DialogControl":
        return cls(int(payload.get("controlId", 0)), int(payload.get("x", 0)), int(payload.get("y", 0)), int(payload.get("width", 0)), int(payload.get("height", 0)), int(payload.get("style", 0)), int(payload.get("exstyle", 0)), payload.get("class", ""), payload.get("title", ""), bytes.fromhex(str(payload.get("creationDataHex", ""))), int(payload.get("helpId", 0)))


@dataclass
class DialogResource:
    x: int
    y: int
    width: int
    height: int
    style: int
    exstyle: int = 0
    title: str = ""
    menu: int | str = ""
    window_class: int | str = ""
    font_size: int | None = None
    font_name: str | None = None
    font_weight: int = 400
    font_italic: bool = False
    font_charset: int = 1
    controls: list[DialogControl] = field(default_factory=list)
    extended: bool = False
    help_id: int = 0
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"x": self.x, "y": self.y, "width": self.width, "height": self.height, "style": self.style, "exstyle": self.exstyle, "title": self.title, "menu": self.menu, "windowClass": self.window_class, "fontSize": self.font_size, "fontName": self.font_name, "fontWeight": self.font_weight, "fontItalic": self.font_italic, "fontCharset": self.font_charset, "extended": self.extended, "helpId": self.help_id, "version": self.version, "controls": [control.to_dict() for control in self.controls]}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DialogResource":
        return cls(int(payload.get("x", 0)), int(payload.get("y", 0)), int(payload.get("width", 100)), int(payload.get("height", 60)), int(payload.get("style", 0)), int(payload.get("exstyle", 0)), str(payload.get("title", "")), payload.get("menu", ""), payload.get("windowClass", ""), None if payload.get("fontSize") is None else int(payload["fontSize"]), payload.get("fontName"), int(payload.get("fontWeight", 400)), bool(payload.get("fontItalic", False)), int(payload.get("fontCharset", 1)), [DialogControl.from_dict(item) for item in payload.get("controls", [])], bool(payload.get("extended", False)), int(payload.get("helpId", 0)), int(payload.get("version", 1)))

    @classmethod
    def parse(cls, data: bytes) -> "DialogResource":
        reader = _Reader(data)
        first = reader.word()
        second = reader.word()
        if first == 1 and second == DIALOGEX_SIGNATURE:
            version = first
            help_id = reader.dword()
            exstyle = reader.dword()
            style = reader.dword()
            count = reader.word()
            x, y, width, height = reader.signed_words(4)
            extended = True
        else:
            help_id = 0
            style = first | (second << 16)
            exstyle = reader.dword()
            count = reader.word()
            x, y, width, height = reader.signed_words(4)
            version = 0
            extended = False
        menu = reader.ordinal_or_string()
        window_class = reader.ordinal_or_string()
        title = reader.string()
        font_size = None
        font_name = None
        font_weight = 400
        font_italic = False
        font_charset = 1
        if style & DS_SETFONT:
            font_size = reader.word()
            if extended:
                font_weight = reader.word()
                font_italic = bool(reader.byte())
                font_charset = reader.byte()
            font_name = reader.string()
        reader.align4()
        controls: list[DialogControl] = []
        for _ in range(count):
            reader.align4()
            if extended:
                control_help = reader.dword()
                control_exstyle = reader.dword()
                control_style = reader.dword()
                control_id = reader.word()
                cx, cy, cw, ch = reader.signed_words(4)
            else:
                control_help = 0
                control_exstyle = reader.dword()
                control_style = reader.dword()
                cx, cy, cw, ch, control_id = reader.signed_words(5)
            class_name = reader.ordinal_or_string()
            control_title = reader.ordinal_or_string()
            extra_size = reader.word()
            creation_data = reader.take(extra_size)
            controls.append(DialogControl(control_id, cx, cy, cw, ch, control_style, control_exstyle, class_name, control_title, creation_data, control_help))
        if reader.offset != len(data):
            raise DialogResourceError("trailing bytes after dialog resource")
        return cls(x, y, width, height, style, exstyle, title, menu, window_class, font_size, font_name, font_weight, font_italic, font_charset, controls, extended, help_id, version)

    def validate(self) -> dict[str, object]:
        errors: list[str] = []
        warnings: list[str] = []
        for value, name in ((self.x, "x"), (self.y, "y"), (self.width, "width"), (self.height, "height")):
            if not -32768 <= value <= 32767:
                errors.append(f"{name} must fit signed WORD")
        if len(self.controls) > 0xFFFF:
            errors.append("too many dialog controls")
        if self.style & DS_SETFONT and (self.font_size is None or self.font_name is None):
            errors.append("DS_SETFONT requires font_size and font_name")
        seen_ids: set[int] = set()
        for index, control in enumerate(self.controls):
            if not 0 <= control.control_id <= 0xFFFF or not 0 <= control.help_id <= 0xFFFFFFFF:
                errors.append(f"control {index}: invalid identifier")
            if control.control_id in seen_ids:
                warnings.append(f"control {index}: duplicate control ID {control.control_id}")
            seen_ids.add(control.control_id)
            if not isinstance(control.class_name, (int, str)) or not isinstance(control.title, (int, str)):
                errors.append(f"control {index}: class and title must be ordinal or string")
            for value, name in ((control.x, "x"), (control.y, "y"), (control.width, "width"), (control.height, "height")):
                if not -32768 <= value <= 32767:
                    errors.append(f"control {index} {name} must fit signed WORD")
            if control.class_name == 0x0080 and not control.title:
                warnings.append(f"control {index}: button has an empty caption")
        return {"valid": not errors, "errors": errors, "warnings": warnings, "controlCount": len(self.controls), "extended": self.extended}

    def to_bytes(self) -> bytes:
        report = self.validate()
        if report["errors"]:
            raise DialogResourceError("invalid dialog: " + "; ".join(report["errors"]))
        self._validate()
        out = bytearray()
        if self.extended:
            out.extend(struct.pack("<HHIIIHhhhh", self.version, DIALOGEX_SIGNATURE, self.help_id, self.exstyle, self.style, len(self.controls), self.x, self.y, self.width, self.height))
        else:
            out.extend(struct.pack("<IIHhhhh", self.style, self.exstyle, len(self.controls), self.x, self.y, self.width, self.height))
        out.extend(_encode_ordinal_or_string(self.menu))
        out.extend(_encode_ordinal_or_string(self.window_class))
        out.extend(_encode_string(self.title))
        if self.style & DS_SETFONT:
            if self.font_size is None or self.font_name is None:
                raise DialogResourceError("DS_SETFONT requires font_size and font_name")
            out.extend(struct.pack("<H", self.font_size))
            if self.extended:
                out.extend(struct.pack("<HBB", self.font_weight, int(self.font_italic), self.font_charset))
            out.extend(_encode_string(self.font_name))
        _align4(out)
        for control in self.controls:
            _align4(out)
            if self.extended:
                out.extend(struct.pack("<IIIHhhhh", control.help_id, control.exstyle, control.style, control.control_id, control.x, control.y, control.width, control.height))
            else:
                out.extend(struct.pack("<IIhhhhH", control.exstyle, control.style, control.x, control.y, control.width, control.height, control.control_id))
            out.extend(_encode_ordinal_or_string(control.class_name))
            out.extend(_encode_ordinal_or_string(control.title))
            if len(control.creation_data) > 0xFFFF:
                raise DialogResourceError("creation data is too large")
            out.extend(struct.pack("<H", len(control.creation_data)))
            out.extend(control.creation_data)
        return bytes(out)

    def _validate(self) -> None:
        for value, name in ((self.x, "x"), (self.y, "y"), (self.width, "width"), (self.height, "height")):
            if not -32768 <= value <= 32767:
                raise DialogResourceError(f"{name} must fit signed WORD")
        if len(self.controls) > 0xFFFF:
            raise DialogResourceError("too many dialog controls")
        if not 0 <= self.font_weight <= 0xFFFF or not 0 <= self.font_charset <= 0xFF:
            raise DialogResourceError("invalid font attributes")
        for control in self.controls:
            if not 0 <= control.control_id <= 0xFFFF or not 0 <= control.help_id <= 0xFFFFFFFF:
                raise DialogResourceError("invalid control identifier")
            for value, name in ((control.x, "control x"), (control.y, "control y"), (control.width, "control width"), (control.height, "control height")):
                if not -32768 <= value <= 32767:
                    raise DialogResourceError(f"{name} must fit signed WORD")


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = bytes(data)
        self.offset = 0

    def take(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise DialogResourceError("dialog resource is truncated")
        result = self.data[self.offset : self.offset + length]
        self.offset += length
        return result

    def word(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def dword(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def dword_after(self, first_word: int) -> int:
        return first_word | (self.word() << 16)

    def byte(self) -> int:
        return self.take(1)[0]

    def signed_words(self, count: int) -> tuple[int, ...]:
        return struct.unpack("<" + "h" * count, self.take(2 * count))

    def string(self) -> str:
        start = self.offset
        while True:
            if self.offset + 2 > len(self.data):
                raise DialogResourceError("unterminated UTF-16 string")
            if self.data[self.offset : self.offset + 2] == b"\x00\x00":
                raw = self.data[start : self.offset]
                self.offset += 2
                try:
                    return raw.decode("utf-16le")
                except UnicodeDecodeError as exc:
                    raise DialogResourceError("invalid UTF-16 string") from exc
            self.offset += 2

    def ordinal_or_string(self) -> int | str:
        marker = self.word()
        if marker == 0:
            return ""
        if marker == DIALOGEX_SIGNATURE:
            return self.word()
        start = self.offset - 2
        while True:
            if self.offset + 2 > len(self.data):
                raise DialogResourceError("unterminated UTF-16 ordinal/string field")
            if self.data[self.offset : self.offset + 2] == b"\x00\x00":
                raw = self.data[start : self.offset]
                self.offset += 2
                try:
                    return raw.decode("utf-16le")
                except UnicodeDecodeError as exc:
                    raise DialogResourceError("invalid UTF-16 field") from exc
            self.offset += 2

    def align4(self) -> None:
        self.offset = (self.offset + 3) & ~3
        if self.offset > len(self.data):
            raise DialogResourceError("invalid dialog alignment")


def _encode_string(value: str) -> bytes:
    if "\x00" in value:
        raise DialogResourceError("strings cannot contain NUL")
    return value.encode("utf-16le") + b"\x00\x00"


def _encode_ordinal_or_string(value: int | str) -> bytes:
    if isinstance(value, int):
        if not 0 <= value <= 0xFFFF:
            raise DialogResourceError("ordinal must fit WORD")
        return struct.pack("<HH", DIALOGEX_SIGNATURE, value)
    if not isinstance(value, str):
        raise DialogResourceError("field must be an ordinal or string")
    return _encode_string(value)


def _align4(buffer: bytearray) -> None:
    buffer.extend(b"\x00" * ((-len(buffer)) & 3))

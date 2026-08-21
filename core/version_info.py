from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field

_VERSION = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


@dataclass
class VersionInfo:
    file_version: str = "1.0.0.0"
    product_version: str = "1.0.0.0"
    strings: dict[str, str] = field(default_factory=dict)
    translations: list[int] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def validate(self) -> dict[str, list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        for field_name, value in (("file_version", self.file_version), ("product_version", self.product_version)):
            if not _VERSION.fullmatch(value):
                errors.append(f"{field_name} must have four numeric components")
        if not self.strings.get("FileDescription"):
            warnings.append("FileDescription is empty")
        if not self.translations:
            warnings.append("no language translations declared")
        warnings.extend(self.warnings)
        if any(not isinstance(value, str) for value in self.strings.values()):
            errors.append("all version strings must be text")
        return {"errors": errors, "warnings": warnings, "valid": not errors}

    def set_string(self, key: str, value: str) -> None:
        if not key.strip():
            raise ValueError("version string key cannot be empty")
        self.strings[key] = value

    def set_translation(self, language_id: int) -> None:
        if not 0 <= language_id <= 0xFFFF:
            raise ValueError("language id must fit WORD")
        if language_id not in self.translations:
            self.translations.append(language_id)
            self.translations.sort()

    def to_bytes(self, codepage: int = 1200) -> bytes:
        report = self.validate()
        if report["errors"]:
            raise ValueError("cannot serialize invalid VersionInfo: " + "; ".join(report["errors"]))
        if not 0 <= codepage <= 0xFFFF:
            raise ValueError("codepage must fit WORD")
        file_parts = _version_parts(self.file_version)
        product_parts = _version_parts(self.product_version)
        fixed = struct.pack(
            "<13I",
            0xFEEF04BD,
            0x00010000,
            (file_parts[0] << 16) | file_parts[1],
            (file_parts[2] << 16) | file_parts[3],
            (product_parts[0] << 16) | product_parts[1],
            (product_parts[2] << 16) | product_parts[3],
            0,
            0,
            0x00040004,
            1,
            0,
            0,
            0,
        )
        translations = self.translations or [0x0409]
        values = {"FileVersion": self.file_version, "ProductVersion": self.product_version, **self.strings}
        tables = []
        for language in translations:
            strings = [_vs_block(key, value.encode("utf-16le") + b"\x00\x00", 1) for key, value in sorted(values.items())]
            tables.append(_vs_block(f"{language:04X}{codepage:04X}", b"", 1, strings))
        string_file = _vs_block("StringFileInfo", b"", 1, tables)
        translation_value = b"".join(struct.pack("<I", (codepage << 16) | language) for language in translations)
        var = _vs_block("Translation", translation_value, 0)
        var_file = _vs_block("VarFileInfo", b"", 1, [var])
        return _vs_block("VS_VERSION_INFO", fixed, 0, [string_file, var_file])

    @classmethod
    def from_bytes(cls, data: bytes) -> VersionInfo:
        data = bytes(data)
        if len(data) < 2:
            raise ValueError("VERSION resource has invalid root length")
        root_length = struct.unpack_from("<H", data, 0)[0]
        if root_length < 2 or root_length > len(data):
            raise ValueError("VERSION resource has invalid root length")
        trailing = data[root_length:]
        if len(trailing) > 64:
            raise ValueError("VERSION resource has excessive trailing data")
        root = _parse_vs_block(data[:root_length], 0, root_length)
        if root.key != "VS_VERSION_INFO" or len(root.value) < 52:
            raise ValueError("invalid VS_VERSION_INFO resource")
        fixed = struct.unpack_from("<13I", root.value, 0)
        if fixed[0] != 0xFEEF04BD:
            raise ValueError("invalid VS_FIXEDFILEINFO signature")
        file_version = _version_text(fixed[2], fixed[3])
        product_version = _version_text(fixed[4], fixed[5])
        strings: dict[str, str] = {}
        translations: list[int] = []
        for child in root.children:
            if child.key == "StringFileInfo":
                for table in child.children:
                    if len(table.key) >= 4:
                        try:
                            translations.append(int(table.key[:4], 16))
                        except ValueError:
                            pass
                    for value in table.children:
                        if value.type == 1 and value.key not in {"FileVersion", "ProductVersion"}:
                            strings[value.key] = value.value.decode("utf-16le").rstrip("\x00")
            elif child.key == "VarFileInfo":
                for value in child.children:
                    if value.key == "Translation" and len(value.value) % 4 == 0:
                        for (translation,) in struct.iter_unpack("<I", value.value):
                            translations.append(translation & 0xFFFF)
        compatibility_warnings = [f"ignored {len(trailing)} trailing VERSIONINFO bytes" ] if trailing else []
        return cls(file_version, product_version, strings, sorted(set(translations)), compatibility_warnings)

    def to_json(self) -> str:
        return json.dumps(
            {
                "format": "resource_studio.version_info.v1",
                "fileVersion": self.file_version,
                "productVersion": self.product_version,
                "strings": dict(sorted(self.strings.items())),
                "translations": self.translations,
                "warnings": list(self.warnings),
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n"

    def to_rc(self, resource_id: int | str = 1, codepage: int = 1200) -> str:
        report = self.validate()
        if report["errors"]:
            raise ValueError("cannot serialize invalid VersionInfo: " + "; ".join(report["errors"]))
        if not isinstance(resource_id, (int, str)) or (isinstance(resource_id, int) and not 1 <= resource_id <= 0xFFFF):
            raise ValueError("resource_id must be a valid integer ID or string")
        if not 0 <= codepage <= 0xFFFF:
            raise ValueError("codepage must fit WORD")
        lines = [
            f"{resource_id} VERSIONINFO",
            f" FILEVERSION {self.file_version.replace('.', ',')}",
            f" PRODUCTVERSION {self.product_version.replace('.', ',')}",
            " BEGIN",
            '  BLOCK "StringFileInfo"',
            "  BEGIN",
            f'   BLOCK "{(self.translations[0] if self.translations else 0x0409):04X}{codepage:04X}"',
            "   BEGIN",
        ]
        values = {"FileVersion": self.file_version, "ProductVersion": self.product_version, **self.strings}
        for key, value in sorted(values.items()):
            lines.append(f'    VALUE "{_rc_escape(key)}", "{_rc_escape(value)}"')
        lines.extend(["   END", "  END", '  BLOCK "VarFileInfo"', "  BEGIN"])
        translations = ", ".join(f"0x{value:04X}" for value in self.translations) or "0x0409"
        lines.append(f'   VALUE "Translation", {translations}')
        lines.extend(["  END", " END", "END", ""])
        return "\n".join(lines)

    @classmethod
    def from_rc(cls, text: str) -> VersionInfo:
        if not isinstance(text, str) or "VERSIONINFO" not in text or "BEGIN" not in text:
            raise ValueError("invalid VERSIONINFO RC text")
        file_match = re.search(r"\bFILEVERSION\s+(\d+),(\d+),(\d+),(\d+)", text)
        product_match = re.search(r"\bPRODUCTVERSION\s+(\d+),(\d+),(\d+),(\d+)", text)
        if file_match is None or product_match is None:
            raise ValueError("VERSIONINFO RC text lacks FILEVERSION or PRODUCTVERSION")
        values: dict[str, str] = {}
        for match in re.finditer(r'VALUE\s+"((?:\\.|[^"\\])*)"\s*,\s*"((?:\\.|[^"\\])*)"', text):
            key, value = _rc_unescape(match.group(1)), _rc_unescape(match.group(2))
            if key not in {"FileVersion", "ProductVersion"}:
                values[key] = value
        translation_match = re.search(r'VALUE\s+"Translation"\s*,([^\r\n]+)', text)
        translations: list[int] = []
        if translation_match:
            for token in translation_match.group(1).split(","):
                token = token.strip()
                if token:
                    translations.append(int(token, 0))
        return cls(
            file_version=".".join(file_match.groups()),
            product_version=".".join(product_match.groups()),
            strings=values,
            translations=translations,
        )

    @classmethod
    def from_json(cls, text: str) -> VersionInfo:
        payload = json.loads(text)
        if payload.get("format") != "resource_studio.version_info.v1":
            raise ValueError("unsupported version info format")
        return cls(
            file_version=str(payload.get("fileVersion", "1.0.0.0")),
            product_version=str(payload.get("productVersion", "1.0.0.0")),
            strings={str(key): str(value) for key, value in (payload.get("strings") or {}).items()},
            translations=[int(language) for language in payload.get("translations", [])],
            warnings=[str(item) for item in payload.get("warnings", [])],
        )


@dataclass(frozen=True)
class _VSBlock:
    key: str
    value: bytes
    type: int
    children: tuple[_VSBlock, ...] = ()


def _version_parts(value: str) -> tuple[int, int, int, int]:
    parts = tuple(int(part) for part in value.split("."))
    if len(parts) != 4 or any(part > 0xFFFF for part in parts):
        raise ValueError("version components must fit WORD")
    return parts  # type: ignore[return-value]


def _version_text(high: int, low: int) -> str:
    return f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}"


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _vs_block(key: str, value: bytes, type: int, children: list[bytes] | None = None) -> bytes:
    body = struct.pack("<HHH", 0, len(value) // 2 if type == 1 else len(value), type)
    body += key.encode("utf-16le") + b"\x00\x00"
    body += b"\x00" * ((_align4(len(body)) - len(body)) % 4)
    body += value
    body += b"\x00" * ((_align4(len(body)) - len(body)) % 4)
    body += b"".join(children or [])
    body += b"\x00" * ((_align4(len(body)) - len(body)) % 4)
    if len(body) > 0xFFFF:
        raise ValueError("VERSION resource block exceeds WORD length")
    return struct.pack("<H", len(body)) + body[2:]


def _parse_vs_block(data: bytes, offset: int, limit: int) -> _VSBlock:
    if offset + 6 > limit:
        raise ValueError("truncated VERSION resource block")
    length, value_length, block_type = struct.unpack_from("<HHH", data, offset)
    end = offset + length
    if length < 6 or end > limit:
        raise ValueError("invalid VERSION resource block length")
    cursor = offset + 6
    chars: list[str] = []
    while cursor + 2 <= end:
        code = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        if code == 0:
            break
        chars.append(chr(code))
    else:
        raise ValueError("unterminated VERSION resource key")
    key = "".join(chars)
    value_start = _align4(cursor)
    value_size = value_length * 2 if block_type == 1 else value_length
    value_end = value_start + value_size
    if value_end > end:
        raise ValueError("VERSION resource value exceeds block")
    value = data[value_start:value_end]
    children: list[_VSBlock] = []
    child_cursor = _align4(value_end)
    while child_cursor + 6 <= end:
        child = _parse_vs_block(data, child_cursor, end)
        children.append(child)
        next_cursor = _align4(child_cursor + struct.unpack_from("<H", data, child_cursor)[0])
        if next_cursor <= child_cursor:
            raise ValueError("VERSION resource child did not advance")
        child_cursor = next_cursor
    return _VSBlock(key, value, block_type, tuple(children))


def _rc_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


def _rc_unescape(value: str) -> str:
    result: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            result.append({"n": "\n", "r": "\r", "\\": "\\", '"': '"'}.get(character, character))
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            result.append(character)
    if escaped:
        result.append("\\")
    return "".join(result)

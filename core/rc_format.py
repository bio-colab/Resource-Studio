from __future__ import annotations

import re
from dataclasses import dataclass, field

from .menu_resources import MF_POPUP, MF_SEPARATOR, MenuItem, MenuResource
from .res_format import ResFile, ResRecord
from .string_table import StringTableBlock, string_table_block_id
from .util import unescape_rc_string
from .version_info import VersionInfo


RC_DEFAULT_LANGUAGE = 1033


def compile_rc(text: str, *, language: int = RC_DEFAULT_LANGUAGE) -> ResFile:
    """Compile the supported RC subset into a RES file."""
    if not 0 <= language <= 0xFFFF:
        raise ValueError("RC language must fit WORD")
    document = RCDocument.from_text(text)
    records: list[ResRecord] = []
    for table in document.string_tables:
        blocks: dict[int, list[str]] = {}
        for raw_id, value in table.entries.items():
            try:
                string_id = int(raw_id, 0)
            except ValueError as exc:
                raise ValueError(f"STRINGTABLE id must be numeric: {raw_id}") from exc
            block_id = string_table_block_id(string_id)
            slots = blocks.setdefault(block_id, [""] * StringTableBlock.SLOT_COUNT)
            slots[(string_id - 1) % StringTableBlock.SLOT_COUNT] = value
        records.extend(ResRecord(6, block_id, language, StringTableBlock(block_id, tuple(slots)).to_bytes()) for block_id, slots in sorted(blocks.items()))
    for menu in document.menus:
        name: int | str = _parse_rc_id(menu.resource_id)
        records.append(ResRecord(4, name, language, MenuResource(menu.items).to_bytes()))
    for version in document.versions:
        records.append(ResRecord(16, 1, language, version.to_bytes()))
    return ResFile(records)


def decompile_res(data: bytes) -> str:
    """Decompile supported RES records into a loss-aware RC subset."""
    resource_file = ResFile.from_bytes(data)
    chunks: list[str] = []
    for record in resource_file.records:
        resource_type = _resource_type_name(record.resource_type)
        name = _rc_id(record.name)
        if resource_type == "STRING":
            block = StringTableBlock.from_bytes(int(record.name), record.data)
            lines = ["STRINGTABLE", "BEGIN"]
            for index, value in enumerate(block.strings):
                if value:
                    lines.append(f'  {block.first_string_id + index} "{_escape(value)}"')
            lines.extend(["END", ""])
            chunks.append("\n".join(lines))
        elif resource_type == "MENU":
            chunks.append(RCMenus(name, MenuResource.parse(record.data).items).to_rc())
        elif resource_type == "VERSION":
            chunks.append(VersionInfo.from_bytes(record.data).to_rc())
        else:
            chunks.append(f"// UNSUPPORTED RES {resource_type}:{name}:{record.language} size={len(record.data)}\n")
    return "".join(chunks)


def _parse_rc_id(value: str) -> int | str:
    try:
        return int(value, 0)
    except ValueError:
        return value


def _rc_id(value: int | str) -> str:
    return str(value)


def _resource_type_name(value: int | str) -> str:
    return {4: "MENU", 6: "STRING", 16: "VERSION"}.get(value, str(value))


@dataclass
class RCStringTable:
    entries: dict[str, str] = field(default_factory=dict)

    def to_rc(self) -> str:
        lines = ["STRINGTABLE", "BEGIN"]
        lines.extend(f'  {key} "{_escape(value)}"' for key, value in sorted(self.entries.items()))
        lines.extend(["END", ""])
        return "\n".join(lines)


@dataclass
class RCMenus:
    resource_id: str
    items: list[MenuItem]

    def to_rc(self) -> str:
        lines = [f"{self.resource_id} MENU", "BEGIN"]
        _menu_to_lines(self.items, lines, 1)
        lines.extend(["END", ""])
        return "\n".join(lines)


@dataclass
class RCDocument:
    string_tables: list[RCStringTable] = field(default_factory=list)
    menus: list[RCMenus] = field(default_factory=list)
    versions: list[VersionInfo] = field(default_factory=list)

    @classmethod
    def from_text(cls, text: str) -> RCDocument:
        if not isinstance(text, str):
            raise ValueError("RC text must be a string")
        document = cls()
        lines = text.splitlines()
        index = 0
        while index < len(lines):
            line = _strip_comment(lines[index]).strip()
            if not line:
                index += 1
                continue
            if line.upper() == "STRINGTABLE" or re.match(r"^\S+\s+STRINGTABLE$", line, re.IGNORECASE):
                block, index = _parse_string_table(lines, index + 1)
                document.string_tables.append(block)
                continue
            match = re.match(r"^(\S+)\s+(MENU|MENUEX)\s*$", line, re.IGNORECASE)
            if match:
                block, index = _parse_menu(lines, index + 1, match.group(1))
                document.menus.append(block)
                continue
            if re.search(r"\bVERSIONINFO\b", line, re.IGNORECASE):
                block_lines, index = _collect_begin_end(lines, index)
                document.versions.append(VersionInfo.from_rc("\n".join(block_lines)))
                continue
            index += 1
        return document

    def to_rc(self) -> str:
        return "".join([block.to_rc() for block in self.string_tables] + [menu.to_rc() for menu in self.menus] + [version.to_rc() for version in self.versions])


def _parse_string_table(lines: list[str], index: int) -> tuple[RCStringTable, int]:
    index = _skip_begin(lines, index)
    entries: dict[str, str] = {}
    while index < len(lines):
        line = _strip_comment(lines[index]).strip()
        if line.upper() == "END":
            return RCStringTable(entries), index + 1
        match = re.match(r'^(\S+)\s+"((?:\\.|[^"\\])*)"\s*$', line)
        if not match:
            raise ValueError(f"invalid STRINGTABLE line: {line}")
        entries[match.group(1)] = unescape_rc_string(match.group(2))
        index += 1
    raise ValueError("unterminated STRINGTABLE")


def _parse_menu(lines: list[str], index: int, resource_id: str) -> tuple[RCMenus, int]:
    index = _skip_begin(lines, index)
    items, index = _parse_menu_level(lines, index)
    return RCMenus(resource_id, items), index


def _parse_menu_level(lines: list[str], index: int) -> tuple[list[MenuItem], int]:
    items: list[MenuItem] = []
    while index < len(lines):
        line = _strip_comment(lines[index]).strip()
        if line.upper() == "END":
            return items, index + 1
        popup = re.match(r'^POPUP\s+"((?:\\.|[^"\\])*)"\s*$', line, re.IGNORECASE)
        if popup:
            children, index = _parse_menu_level(lines, _skip_begin(lines, index + 1))
            items.append(MenuItem(0, unescape_rc_string(popup.group(1)), MF_POPUP, children))
            continue
        separator = re.match(r"^MENUITEM\s+SEPARATOR\s*$", line, re.IGNORECASE)
        if separator:
            items.append(MenuItem(0, "", MF_SEPARATOR))
            index += 1
            continue
        item = re.match(r'^MENUITEM\s+"((?:\\.|[^"\\])*)"\s*,\s*([^,\s]+)', line, re.IGNORECASE)
        if item:
            try:
                item_id = int(item.group(2), 0)
            except ValueError:
                item_id = 0
            items.append(MenuItem(item_id, unescape_rc_string(item.group(1))))
            index += 1
            continue
        raise ValueError(f"invalid MENU line: {line}")
    raise ValueError("unterminated MENU")


def _collect_begin_end(lines: list[str], start: int) -> tuple[list[str], int]:
    depth = 0
    seen_begin = False
    collected: list[str] = []
    for index in range(start, len(lines)):
        line = lines[index]
        upper = line.strip().upper()
        if re.search(r"\bBEGIN\b", upper):
            depth += 1
            seen_begin = True
        if re.search(r"\bEND\b", upper):
            depth -= 1
        collected.append(line)
        if seen_begin and depth == 0 and index > start:
            return collected, index + 1
    raise ValueError("unterminated RC block")


def _skip_begin(lines: list[str], index: int) -> int:
    while index < len(lines) and not _strip_comment(lines[index]).strip():
        index += 1
    if index < len(lines) and _strip_comment(lines[index]).strip().upper() == "BEGIN":
        return index + 1
    raise ValueError("RC block must contain BEGIN")


def _menu_to_lines(items: list[MenuItem], lines: list[str], depth: int) -> None:
    prefix = "  " * depth
    for item in items:
        if item.is_separator:
            lines.append(prefix + "MENUITEM SEPARATOR")
        elif item.children:
            lines.append(prefix + f'POPUP "{_escape(item.text)}"')
            lines.append(prefix + "BEGIN")
            _menu_to_lines(item.children, lines, depth + 1)
            lines.append(prefix + "END")
        else:
            lines.append(prefix + f'MENUITEM "{_escape(item.text)}", {item.item_id}')


def _strip_comment(line: str) -> str:
    return line.split("//", 1)[0]


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")



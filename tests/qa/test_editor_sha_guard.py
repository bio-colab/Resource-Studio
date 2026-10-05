from __future__ import annotations

import hashlib
import struct
import tempfile
from pathlib import Path

from core.image_resources import IconCursorEntry, IconCursorGroup
from core.menu_resources import MenuItem, MenuResource
from core.pe_writer import LiefPEWriter


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def dib() -> bytes:
    return struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 24, 0, 16, 0, 0, 0, 0) + b"\x00" * 16


def main() -> None:
    original_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    menu = MenuResource([MenuItem(1, "File")]).to_bytes()
    group = IconCursorGroup("ICON", (IconCursorEntry(16, 16, 0, 1, 32, 100, 7),)).to_bytes()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        writer = LiefPEWriter()
        bitmap_output = directory / "bitmap.dll"
        menu_output = directory / "menu.dll"
        icon_output = directory / "icon.dll"
        assert writer.add_typed_resource(FIXTURE, bitmap_output, "BITMAP", 901, 1033, dib()).verified
        assert writer.add_typed_resource(FIXTURE, menu_output, "MENU", 902, 1033, menu).verified
        assert writer.add_typed_resource(FIXTURE, icon_output, "GROUP_ICON", 903, 1033, group).verified
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == original_hash
    print("editor-sha-guard-tests: passed")


if __name__ == "__main__":
    main()

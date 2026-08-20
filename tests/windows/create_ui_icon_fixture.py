from __future__ import annotations

import struct
import sys
from pathlib import Path

from core.pe_writer import LiefPEWriter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests" / "fixtures" / "sample.dll"


def icon_dib(width: int = 2, height: int = 2) -> bytes:
    row_stride = width * 4
    header = struct.pack("<IiiHHIIiiII", 40, width, height * 2, 1, 32, 0, row_stride * height, 0, 0, 0, 0)
    pixels = bytes(range(row_stride * height))
    mask = bytes(((width + 31) // 32) * 4 * height)
    return header + pixels + mask


def main(output: Path) -> None:
    raw = icon_dib()
    group = struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHIH", 2, 2, 0, 0, 1, 32, len(raw), 1)
    LiefPEWriter().add_resource(SOURCE, output, "ICON", 1, 1033, raw)
    temporary = output.with_suffix(".group.dll")
    LiefPEWriter().add_resource(output, temporary, "GROUP_ICON", 1, 1033, group)
    output.unlink()
    temporary.rename(output)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_ui_icon_fixture.py OUTPUT")
    main(Path(sys.argv[1]).resolve())

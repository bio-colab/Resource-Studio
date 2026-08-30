from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from core.image_resources import BitmapResource, IconCursorEntry, IconCursorGroup, ImageResourceError
from core.pe_writer import LiefPEWriter, PEWriterError


def dib() -> bytes:
    header = struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 24, 0, 16, 0, 0, 0, 0)
    return header + b"\x00" * 16


def main() -> None:
    bitmap = BitmapResource.from_dib(dib())
    assert (bitmap.width, bitmap.height, bitmap.bit_count) == (2, 2, 24)
    bmp = bitmap.to_bmp()
    restored = BitmapResource.from_bmp(bmp)
    assert restored.to_dib() == bitmap.to_dib()
    assert LiefPEWriter.validate_resource_payload("BITMAP", dib()) == dib()

    group = IconCursorGroup("ICON", (IconCursorEntry(0, 0, 0, 1, 32, 100, 7),))
    restored_group = IconCursorGroup.parse(group.to_bytes())
    assert LiefPEWriter.validate_resource_payload("GROUP_ICON", group.to_bytes()) == group.to_bytes()
    assert restored_group.kind == "ICON"
    assert restored_group.dimensions() == ((256, 256),)

    source = Path("tests/fixtures/sample.dll").resolve()
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "bitmap-added.dll"
        result = LiefPEWriter().add_typed_resource(source, output, "BITMAP", 999, 1033, dib())
        assert result.verified is True
        assert output.is_file()
    try:
        IconCursorGroup.parse(b"\x00" * 6)
    except ImageResourceError:
        pass
    else:
        raise AssertionError("truncated image group was accepted")
    print("image-resource-tests: passed")


if __name__ == "__main__":
    main()

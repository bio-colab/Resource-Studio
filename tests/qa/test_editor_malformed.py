from __future__ import annotations

import struct

from core.image_resources import BitmapResource, IconCursorGroup, ImageResourceError
from core.menu_resources import MenuResource, MenuResourceError


CASES = (b"", b"\x00" * 5, b"BM\x00", b"\x00\x00\x01\x00\x01\x00")


def main() -> None:
    for payload in CASES:
        for parser in (BitmapResource.from_dib, BitmapResource.from_bmp, IconCursorGroup.parse, MenuResource.parse):
            try:
                parser(payload)
            except (ImageResourceError, MenuResourceError, struct.error):
                continue
            else:
                raise AssertionError(f"malformed payload accepted by {parser.__qualname__}")
    print("editor-malformed-tests: passed")


if __name__ == "__main__":
    main()

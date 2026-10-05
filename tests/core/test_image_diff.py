from __future__ import annotations

import struct

from core.diff import diff_image_payloads, merge_selected_resources
from core.project import ResourceEntry


def dib(pixel: int = 0) -> bytes:
    header = struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 24, 0, 16, 0, 0, 0, 0)
    return header + bytes([pixel]) * 16


def main() -> None:
    unchanged = diff_image_payloads(dib(), dib(), kind="bitmap")
    assert unchanged.status == "unchanged"
    modified = diff_image_payloads(dib(), dib(1), kind="bitmap")
    assert modified.status == "modified"
    assert modified.before["width"] == 2
    assert modified.after["sha256"] != modified.before["sha256"]
    assert modified.children

    base = (ResourceEntry("BITMAP", "1", 1033, dib()), ResourceEntry("MENU", "1", 1033, b"old"))
    incoming = (ResourceEntry("BITMAP", "1", 1033, dib(1)), ResourceEntry("MENU", "1", 1033, b"new"))
    merged = merge_selected_resources(base, incoming, [("BITMAP", "1", 1033)])
    assert merged[0].data == dib(1)
    assert merged[1].data == b"old"
    assert base[0].data == dib()
    print("image-diff-tests: passed")


if __name__ == "__main__":
    main()

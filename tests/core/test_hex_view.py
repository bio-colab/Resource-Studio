from __future__ import annotations

from core.hex_view import HexViewer
from core.resource_index import ResourceIndex, ResourceIndexItem


def main() -> None:
    viewer = HexViewer(b"ABC\x00xyz")
    chunk = viewer.slice(1, 4)
    assert chunk.offset == 1
    assert chunk.hex() == "42 43 00 78"
    assert chunk.ascii() == "BC.x"
    assert chunk.as_c_array() == "0x42, 0x43, 0x00, 0x78"
    assert chunk.base64() == "QkMAeA=="
    assert viewer.find(b"xyz") == 4
    assert viewer.find(b"missing") == -1
    index = ResourceIndex((ResourceIndexItem("RCDATA", "1", 1033, 4, "hash", 3),))
    indexed = viewer.resource_slice(index, "RCDATA", "1", 1033, 3)
    assert indexed.offset == 3 and indexed.data == b"\x00xy"
    try:
        viewer.slice(99)
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-range slice was accepted")
    print("hex-view-tests: passed")


if __name__ == "__main__":
    main()

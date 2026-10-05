from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from core.dialog_resources import DialogResource
from core.image_resources import BitmapResource
from core.menu_resources import MenuItem, MenuResource
from core.preview import PreviewEngine
from core.string_table import StringTableBlock
from core.version_info import VersionInfo


def main() -> None:
    manifest = PreviewEngine.preview("MANIFEST", b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity name="x" version="1.0.0.0" type="win32" /></assembly>', resource_name="1", language=1033)
    assert manifest.kind == "xml" and manifest.summary["valid"]
    version = VersionInfo(strings={"FileDescription": "Preview"}, translations=[0x0409])
    version_preview = PreviewEngine.preview("VERSION", version.to_bytes(), resource_name="1", language=1033)
    assert version_preview.kind == "version-info" and version_preview.summary["fileVersion"] == "1.0.0.0"
    menu = MenuResource([MenuItem(1, "File", children=[MenuItem(2, "Open")])])
    menu_preview = PreviewEngine.preview("MENU", menu.to_bytes(), resource_name="1", language=1033)
    assert menu_preview.kind == "menu-tree" and menu_preview.summary["itemCount"] == 2
    strings = PreviewEngine.preview("STRING", StringTableBlock(1, tuple(["Hello"] + [""] * 15)).to_bytes(), resource_name="1", language=1033)
    assert strings.kind == "string-table" and strings.summary["nonEmptyCount"] == 1
    dib = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 32, 0, 4, 2835, 2835, 0, 0) + b"\x00\x00\xff\x00"
    with tempfile.TemporaryDirectory(prefix="resource-studio-preview-") as temporary:
        output = Path(temporary) / "preview.bmp"
        bitmap = PreviewEngine.preview("BITMAP", dib, resource_name="1", language=1033, output_path=output)
        assert bitmap.kind == "bitmap" and output.read_bytes()[:2] == b"BM"
    raw = PreviewEngine.preview("RCDATA", b"abc", resource_name="9", language=1033, raw_length=2)
    assert raw.kind == "raw" and raw.raw["shown"] == 2
    malformed = PreviewEngine.preview("MENU", b"bad", resource_name="1", language=1033)
    assert malformed.kind == "raw" and malformed.warnings
    print("preview-engine-tests: passed")


if __name__ == "__main__":
    main()

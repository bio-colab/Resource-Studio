from __future__ import annotations

import json
from pathlib import Path

from core.menu_resources import MenuItem, MenuResource
from core.preview import PreviewEngine

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = json.loads((ROOT / "tests" / "golden" / "preview_models.json").read_text(encoding="utf-8"))


def main() -> None:
    manifest_xml = b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity name="x" version="1.0.0.0" type="win32" /></assembly>'
    manifest = PreviewEngine.preview("MANIFEST", manifest_xml, resource_name="1", language=1033)
    assert {"kind": manifest.kind, "title": manifest.title, "valid": manifest.summary["valid"], "format": manifest.model["format"]} == GOLDEN["manifest"]

    menu = PreviewEngine.preview("MENU", MenuResource([MenuItem(1, "File", children=[MenuItem(2, "Open")])]).to_bytes(), resource_name="1", language=1033)
    assert {"kind": menu.kind, "title": menu.title, "itemCount": menu.summary["itemCount"], "topLevelCount": menu.summary["topLevelCount"]} == GOLDEN["menu"]

    raw = PreviewEngine.preview("RCDATA", b"abc", resource_name="9", language=1033, raw_length=2)
    assert {"kind": raw.kind, "shown": raw.raw["shown"], "size": raw.raw["size"]} == GOLDEN["raw"]
    print("preview-golden-tests: passed")


if __name__ == "__main__":
    main()

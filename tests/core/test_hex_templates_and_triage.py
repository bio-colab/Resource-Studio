from __future__ import annotations

from core.hex_templates import build_hex_template


def main() -> None:
    dib = (40).to_bytes(4, "little") + (640).to_bytes(4, "little", signed=True) + (480).to_bytes(4, "little", signed=True) + (1).to_bytes(2, "little") + (32).to_bytes(2, "little") + bytes(24)
    template = build_hex_template("BITMAP", dib)
    assert template["schema"] == "resource_studio.hex_template.v1"
    assert template["template"] == "BITMAPINFOHEADER"
    fields = {field["name"]: field for field in template["fields"]}
    assert fields["biWidth"]["offset"] == 4 and fields["biWidth"]["length"] == 4 and fields["biWidth"]["value"] == 640
    assert fields["biWidth"]["hex"] == "80 02 00 00"
    print("hex-template-tests: passed")


if __name__ == "__main__":
    main()

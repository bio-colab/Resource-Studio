from __future__ import annotations

import struct

from core.dialog_resources import DS_SETFONT, DialogControl, DialogResource, DialogResourceError


def sample(extended: bool = False) -> DialogResource:
    return DialogResource(
        x=10,
        y=20,
        width=180,
        height=90,
        style=DS_SETFONT | 0x50000000,
        exstyle=0x00000008,
        title="Demo",
        menu=0,
        window_class="DialogClass",
        font_size=9,
        font_name="Segoe UI",
        font_weight=500,
        font_italic=True,
        font_charset=1,
        extended=extended,
        help_id=42,
        controls=[
            DialogControl(100, 8, 8, 70, 14, 0x50010000, 0, 0x0082, "OK"),
            DialogControl(101, 90, 8, 70, 14, 0x50010000, 0, "Cancel", "Cancel"),
        ],
    )


def main() -> None:
    for extended in (False, True):
        original = sample(extended)
        payload = original.to_bytes()
        restored = DialogResource.parse(payload)
        assert restored.to_bytes() == payload
        assert restored.title == "Demo"
        assert len(restored.controls) == 2
        assert restored.controls[0].control_id == 100
    try:
        DialogResource.parse(b"\x00\x00")
    except DialogResourceError:
        pass
    else:
        raise AssertionError("truncated dialog must be rejected")
    malformed = sample().to_bytes() + b"\x01"
    try:
        DialogResource.parse(malformed)
    except DialogResourceError:
        pass
    else:
        raise AssertionError("trailing dialog bytes must be rejected")
    assert struct.unpack_from("<I", sample().to_bytes(), 0)[0] == sample().style
    print("dialog-resource-tests: passed")


if __name__ == "__main__":
    main()

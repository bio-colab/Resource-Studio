from __future__ import annotations

from core.res_format import ResFile, ResRecord


def main() -> None:
    source = ResFile(
        [
            ResRecord("RCDATA", 7, 1033, b"abc", version=2),
            ResRecord(6, "TEXT_NAME", 1025, b"\x00\x01", memory_flags=0x30),
        ]
    )
    restored = ResFile.from_bytes(source.to_bytes())
    assert restored.records == source.records
    assert restored.records[0].resource_type == "RCDATA"
    assert restored.records[1].name == "TEXT_NAME"
    try:
        ResFile.from_bytes(source.to_bytes()[:-3])
    except ValueError:
        pass
    else:
        raise AssertionError("truncated RES payload was accepted")
    try:
        ResRecord("\x00", 1, 1033, b"").to_bytes()
    except ValueError:
        pass
    else:
        raise AssertionError("NUL-containing RES identifier was accepted")
    print("res-format-tests: passed")


if __name__ == "__main__":
    main()

from __future__ import annotations

from core.string_table import StringTableBlock, string_table_block_id


def main() -> None:
    values = tuple(["Hello", "مرحبا"] + [""] * 14)
    block = StringTableBlock(2, values)
    restored = StringTableBlock.from_bytes(2, block.to_bytes())
    assert restored == block
    assert restored.first_string_id == 17
    assert restored.get(18) == "مرحبا"
    assert string_table_block_id(1) == 1
    assert string_table_block_id(16) == 1
    assert string_table_block_id(17) == 2
    try:
        StringTableBlock.from_bytes(2, block.to_bytes()[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("truncated STRINGTABLE payload was accepted")
    print("string-table-tests: passed")


if __name__ == "__main__":
    main()

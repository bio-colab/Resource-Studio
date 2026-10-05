"""Regression tests for the chunked _diff_ranges rewrite.

Two guarantees are pinned here:

1. Equivalence — the chunked implementation yields exactly the same
   contiguous ranges as a naive byte-by-byte reference walk on random
   and boundary-shaped inputs (differential fuzz, seeded).
2. End-of-file visibility — a changed range reaching EOF is emitted.
   The pre-2026-08 implementation silently dropped the final open
   range, so appended or truncated tails never appeared in the
   preservation map (a detection blind spot in a forensic tool).
"""
import random
from pathlib import Path

from core.preservation import _diff_ranges, build_preservation_map


def _reference_walk(before: bytes, after: bytes) -> list[tuple[int, int]]:
    """Naive intended-semantics walk, including end-of-file ranges."""
    limit = max(len(before), len(after))
    ranges: list[tuple[int, int]] = []
    start: int | None = None
    for offset in range(limit):
        changed = offset >= len(before) or offset >= len(after) or before[offset] != after[offset]
        if changed and start is None:
            start = offset
        elif not changed and start is not None:
            ranges.append((start, offset - start))
            start = None
    if start is not None:
        ranges.append((start, limit - start))
    return ranges


def test_differential_equivalence() -> None:
    rng = random.Random(20260830)
    for trial in range(600):
        style = trial % 7
        n = rng.randrange(0, 120000)
        before = bytearray(rng.randbytes(n))
        after = bytearray(before)
        if style == 0:
            pass
        elif style == 1 and n:
            for _ in range(rng.randrange(1, 15)):
                i = rng.randrange(n)
                after[i] = (after[i] + 1) % 256
        elif style == 2 and n > 4:
            i = rng.randrange(n)
            j = min(n, i + rng.randrange(1, 3000))
            for k in range(i, j):
                after[k] ^= 0xFF
        elif style == 3:
            after.extend(rng.randbytes(rng.randrange(1, 700)))
        elif style == 4 and n > 4:
            del after[rng.randrange(n):]
        elif style == 5 and n > 8:
            for c in (65535, 65536, 131071, 131072):
                if c < n:
                    after[c] ^= 0xFF
        else:
            after = bytes(rng.randbytes(max(n, 1)))
        got = [(s, l) for s, l in _diff_ranges(bytes(before), bytes(after))]
        want = _reference_walk(bytes(before), bytes(after))
        assert got == want, f"trial={trial} style={style} n={n}"


def test_tail_ranges_are_visible() -> None:
    before = b"\x00" * 100
    assert list(_diff_ranges(before, before + b"\xAA" * 40)) == [(100, 40)]
    assert list(_diff_ranges(before + b"\xAA" * 40, before)) == [(100, 40)]
    assert list(_diff_ranges(before, before[:-1] + b"\xBB" + b"\xCC")) == [(99, 2)]


def test_preservation_map_reports_appended_tail() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "sample.dll"
    data = fixture.read_bytes()
    report = build_preservation_map(
        fixture,
        fixture,
        resource_type="VERSION",
        resource_name="1",
        language=1033,
    )
    assert report.passed is True
    # same file twice: no changes at all
    assert report.changed_bytes == 0
    # appended overlay bytes at EOF must now be reported as UNEXPECTED
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(prefix="resource-studio-tail-") as directory:
        grown = Path(directory) / "grown.dll"
        grown.write_bytes(data + b"SMUGGLED-PAYLOAD" * 32)
        report = build_preservation_map(
            fixture,
            grown,
            resource_type="VERSION",
            resource_name="1",
            language=1033,
        )
        assert report.changed_bytes == len(b"SMUGGLED-PAYLOAD" * 32)
        assert report.unexpected, "EOF tail append must not be dropped"
        assert report.unexpected[0].offset == len(data)
        assert report.passed is False


def main() -> None:
    test_differential_equivalence()
    test_tail_ranges_are_visible()
    test_preservation_map_reports_appended_tail()
    print("diff-ranges-regression-tests: passed")


if __name__ == "__main__":
    main()

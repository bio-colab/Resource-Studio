from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from core.health import PEHealth
from core.image_resources import BitmapResource, IconCursorGroup
from core.menu_resources import MenuResource
from core.version_info import VersionInfo


def dib() -> bytes:
    return struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 24, 0, 16, 0, 0, 0, 0) + b"\x00" * 16


def main() -> None:
    version_seed = VersionInfo(strings={"FileDescription": "fuzz"}, translations=[0x0409]).to_bytes()
    seeds = [b"", b"MZ", dib(), b"\x00\x00\x01\x00\x01\x00", version_seed]
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for seed_index, seed in enumerate(seeds):
            for bit in range(min(len(seed) * 8, 64)):
                mutated = bytearray(seed)
                mutated[bit // 8] ^= 1 << (bit % 8)
                path = root / f"case-{seed_index}-{bit}.bin"
                path.write_bytes(mutated)
                try:
                    report = PEHealth.inspect(path)
                    assert report.is_pe is False
                except ValueError:
                    pass
                for parser in (BitmapResource.from_dib, BitmapResource.from_bmp, IconCursorGroup.parse, MenuResource.parse, VersionInfo.from_bytes):
                    try:
                        parser(bytes(mutated))
                    except (ValueError, struct.error):
                        pass
    print("bounded-fuzz-tests: passed")


if __name__ == "__main__":
    main()

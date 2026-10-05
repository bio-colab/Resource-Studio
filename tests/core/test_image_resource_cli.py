from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from core.pe_writer import LiefPEWriter

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-image-") as temporary:
        root = Path(temporary)
        source = root / "source.dll"
        with_bitmap = root / "with-bitmap.dll"
        bitmap = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 32, 0, 4, 2835, 2835, 0, 0) + b"\x00\x00\xff\x00"
        dib = root / "pixel.dib"
        dib.write_bytes(bitmap)
        shutil.copy2(FIXTURE, source)
        LiefPEWriter().add_typed_resource(source, with_bitmap, "BITMAP", 1, 1033, bitmap)
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        exported = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "image-resource", "export", str(with_bitmap), "--kind", "bitmap", "--name", "1", "--language", "1033", "--output", str(root / "pixel.bmp"), "--json"], capture_output=True, text=True, env=env, check=False)
        assert exported.returncode == 0, exported.stderr
        assert (root / "pixel.bmp").read_bytes()[:2] == b"BM"
        output = root / "output.dll"
        applied = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "image-resource", "apply", str(with_bitmap), "--kind", "bitmap", "--name", "1", "--language", "1033", "--model", str(root / "pixel.bmp"), "--output", str(output), "--json"], capture_output=True, text=True, env=env, check=False)
        assert applied.returncode == 0, applied.stderr
    print("image-resource-cli-tests: passed")


if __name__ == "__main__":
    main()

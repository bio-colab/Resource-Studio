from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from core.image_resources import BitmapResource, icon_cursor_bmp_to_payload, icon_cursor_payload_to_bmp
from core.pe_writer import LiefPEWriter

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def make_icon_dib(width: int = 2, height: int = 2) -> bytes:
    row_stride = width * 4
    header = struct.pack("<IiiHHIIiiII", 40, width, height * 2, 1, 32, 0, row_stride * height, 0, 0, 0, 0)
    xor_pixels = bytes(range(row_stride * height))
    and_mask = bytes(((width + 31) // 32) * 4 * height)
    return header + xor_pixels + and_mask


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    return subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), *arguments], capture_output=True, text=True, env=env, check=False)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-image-payload-") as temporary:
        root = Path(temporary)
        source = root / "source.dll"
        with_icon = root / "with-icon.dll"
        output = root / "output.dll"
        raw = make_icon_dib()
        changed = root / "changed.bin"
        changed.write_bytes(b"icon-payload-v2")
        shutil.copy2(FIXTURE, source)
        LiefPEWriter().add_resource(source, with_icon, "ICON", 1, 1033, raw)

        direct_bmp = icon_cursor_payload_to_bmp(raw, "ICON")
        decoded = BitmapResource.from_bmp(direct_bmp)
        assert direct_bmp[:2] == b"BM"
        assert (decoded.width, decoded.height, decoded.bit_count) == (2, 2, 32)
        assert icon_cursor_bmp_to_payload(direct_bmp, "ICON") == raw
        try:
            from PIL import Image
            import io
            png_buffer = io.BytesIO()
            Image.new("RGBA", (2, 2), (20, 40, 60, 255)).save(png_buffer, format="PNG")
            png_bmp = icon_cursor_payload_to_bmp(png_buffer.getvalue(), "ICON")
            assert png_bmp[:2] == b"BM"
            assert len(icon_cursor_bmp_to_payload(png_buffer.getvalue(), "ICON")) > 40
        except ImportError:
            pass

        exported = root / "exported.bmp"
        result = run_cli("image-payload", "export", str(with_icon), "--kind", "icon", "--resource-id", "1", "--language", "1033", "--output", str(exported), "--format", "bmp", "--json")
        assert result.returncode == 0, result.stderr
        assert exported.read_bytes() == direct_bmp
        assert json.loads(result.stdout)["format"] == "bmp"

        result = run_cli("image-payload", "apply", str(with_icon), "--kind", "icon", "--resource-id", "1", "--language", "1033", "--payload", str(exported), "--format", "bmp", "--output", str(output), "--json")
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["verified"] is True

        raw_export = root / "raw.bin"
        result = run_cli("image-payload", "export", str(output), "--kind", "icon", "--resource-id", "1", "--language", "1033", "--output", str(raw_export), "--format", "raw", "--json")
        assert result.returncode == 0, result.stderr
        assert raw_export.read_bytes() == raw

        result = run_cli("image-payload", "apply", str(with_icon), "--kind", "icon", "--resource-id", "1", "--language", "1033", "--payload", str(changed), "--output", str(root / "raw-output.dll"), "--json")
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["verified"] is True
    print("image-payload-cli-tests: passed")


if __name__ == "__main__":
    main()

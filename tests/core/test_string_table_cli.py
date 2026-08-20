from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core.pe_writer import LiefPEWriter
from core.string_table import StringTableBlock

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-string-table-") as temporary:
        root = Path(temporary)
        source = root / "source.dll"
        model = root / "strings.json"
        output = root / "output.dll"
        with_string = root / "with-string.dll"
        import shutil

        shutil.copy2(FIXTURE, source)
        block = StringTableBlock(1, tuple(["Hello"] + [""] * 15))
        LiefPEWriter().add_typed_resource(source, with_string, "STRING", 1, 1033, block.to_bytes())
        env = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
        exported = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "string-table", "export", str(with_string), "--name", "1", "--language", "1033", "--output", str(model), "--json"], capture_output=True, text=True, env=env, check=False)
        assert exported.returncode == 0, exported.stderr
        payload = json.loads(model.read_text(encoding="utf-8"))
        assert payload["format"] == "resource_studio.string_table.v1"
        assert payload["strings"][0] == "Hello"
        payload["strings"][0] = "Hello from wizard"
        model.write_text(json.dumps(payload), encoding="utf-8")
        applied = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "string-table", "apply", str(with_string), "--name", "1", "--language", "1033", "--model", str(model), "--output", str(output), "--json"], capture_output=True, text=True, env=env, check=False)
        assert applied.returncode == 0, applied.stderr
        reopened = __import__("lief").parse(str(output))
        assert reopened is not None
    print("string-table-cli-tests: passed")


if __name__ == "__main__":
    main()

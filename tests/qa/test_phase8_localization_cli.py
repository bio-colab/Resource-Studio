from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tests" / "fixtures" / "localization_sample.json"


def main() -> None:
    original = CATALOG.read_bytes()
    environment = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
    compare = subprocess.run(
        [sys.executable, str(ROOT / "resource_studio_cli.py"), "localization", "compare", str(CATALOG), "--source-language", "en", "--target-language", "ar", "--json"],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    assert compare.returncode == 0, compare.stderr
    report = json.loads(compare.stdout)
    assert "IDS_ONLY_EN" in report["comparison"]["missing"]
    assert "IDS_EXTRA" in report["comparison"]["extra"]
    with tempfile.TemporaryDirectory(prefix="resource-studio-phase8-") as temp:
        output = Path(temp) / "pseudo.json"
        pseudo = subprocess.run(
            [sys.executable, str(ROOT / "resource_studio_cli.py"), "localization", "pseudo", str(CATALOG), "--source-language", "en", "--target-language", "qps-ploc", "--output", str(output), "--json"],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        assert pseudo.returncode == 0, pseudo.stderr
        assert output.is_file()
        assert "qps-ploc" in output.read_text(encoding="utf-8")
    assert CATALOG.read_bytes() == original
    print("phase8-localization-cli-tests: passed")


if __name__ == "__main__":
    main()

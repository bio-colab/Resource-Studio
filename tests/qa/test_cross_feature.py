from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from core.project import Project


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"
MANIFEST = "<?xml version='1.0'?><assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'><assemblyIdentity name='CrossFeature' version='1.0.0.0'/></assembly>"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "resource_studio_cli.py"), *args],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> None:
    original_hash = sha256(FIXTURE)
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        project = Project.open_pe(FIXTURE, directory / "project")
        project.apply_manifest(MANIFEST)
        output = project.build(directory / "built.dll")
        assert output.is_file()

        validated = cli("validate", str(output), "--strict", "--json")
        assert validated.returncode == 0, validated.stderr
        assert json.loads(validated.stdout)["is_pe"] is True

        compared = cli("diff", str(FIXTURE), str(output), "--json")
        assert compared.returncode == 0, compared.stderr
        assert json.loads(compared.stdout)["changes"]

        report_path = directory / "diff.html"
        reported = cli("report", "diff", str(FIXTURE), str(output), "--format", "html", "--output", str(report_path))
        assert reported.returncode == 0, reported.stderr
        assert report_path.is_file() and "<table>" in report_path.read_text(encoding="utf-8")
    assert sha256(FIXTURE) == original_hash
    print("cross-feature-tests: passed")


if __name__ == "__main__":
    main()

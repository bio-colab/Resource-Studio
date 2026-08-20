from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from core.project import Project
from core.version_info import VersionInfo


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "resource_studio_cli.py"), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    original_hash = sha256(FIXTURE)
    with tempfile.TemporaryDirectory() as temporary:
        temporary_path = Path(temporary)
        listed = run_cli("list", str(FIXTURE), "--json")
        assert listed.returncode == 0, listed.stderr
        resources = json.loads(listed.stdout)
        assert resources and resources[0]["type"] == "MANIFEST"

        indexed = resources[0]
        baseline_artifact = temporary_path / "sample.forensic-baseline.json"
        baseline_result = run_cli("forensic-baseline", str(FIXTURE), "--output", str(baseline_artifact), "--json")
        assert baseline_result.returncode == 0, baseline_result.stderr
        baseline_payload = json.loads(baseline_result.stdout)
        assert baseline_payload["schema"] == "resource_studio.forensic_baseline.v1"
        assert baseline_payload["artifactPath"] == str(baseline_artifact.resolve())
        assert json.loads(baseline_artifact.read_text(encoding="utf-8"))["sha256"] == original_hash

        hex_result = run_cli("hex", str(FIXTURE), "--type", indexed["type"], "--name", indexed["name"], "--language", str(indexed["language"]), "--length", "8", "--json")
        assert hex_result.returncode == 0, hex_result.stderr
        assert json.loads(hex_result.stdout)["size"] <= 8

        version_rc = temporary_path / "version.rc"
        version_rc.write_text(VersionInfo(strings={"FileDescription": "CLI"}, translations=[0x0409]).to_rc(), encoding="utf-8")
        version_json = temporary_path / "version.json"
        converted = run_cli("version-info", str(version_rc), "--output-format", "json", "--output", str(version_json), "--json")
        assert converted.returncode == 0, converted.stderr
        assert json.loads(version_json.read_text(encoding="utf-8"))["format"] == "resource_studio.version_info.v1"

        extracted = temporary_path / "manifest.bin"
        result = run_cli(
            "extract",
            str(FIXTURE),
            "--type",
            "MANIFEST",
            "--name",
            "1",
            "--language",
            "1033",
            "--output",
            str(extracted),
            "--json",
        )
        assert result.returncode == 0, result.stderr
        assert extracted.stat().st_size == resources[0]["size"]

        same_diff = run_cli("diff", str(FIXTURE), str(FIXTURE), "--json")
        assert same_diff.returncode == 0, same_diff.stderr
        assert json.loads(same_diff.stdout)["changes"] == []

        project = Project.open_pe(FIXTURE, temporary_path / "project")
        output = temporary_path / "built.dll"
        built = run_cli("build", str(project.project_dir), "--output", str(output), "--json")
        assert built.returncode == 0, built.stderr
        assert output.is_file()
        assert sha256(FIXTURE) == original_hash

        valid = run_cli("validate", str(output), "--strict", "--json")
        assert valid.returncode == 0, valid.stderr
        assert json.loads(valid.stdout)["is_pe"] is True

        inspected = run_cli("inspect", str(FIXTURE), "--json")
        assert inspected.returncode == 0, inspected.stderr
        assert json.loads(inspected.stdout)["sections"]

        image_diff = run_cli("image-diff", str(extracted), str(extracted), "--kind", "bitmap", "--json")
        assert image_diff.returncode == 0, image_diff.stderr
        assert json.loads(image_diff.stdout)["status"] == "unchanged"

        inspect_report = run_cli("report", "inspect", str(FIXTURE), "--format", "json")
        assert inspect_report.returncode == 0, inspect_report.stderr
        assert json.loads(inspect_report.stdout)["imports"]

        portable = temporary_path / "portable"
        exported = run_cli("export", str(project.project_dir), "--output", str(portable), "--json")
        assert exported.returncode == 0, exported.stderr
        imported_dir = temporary_path / "imported"
        imported = run_cli("import", str(portable), "--project", str(imported_dir), "--json")
        assert imported.returncode == 0, imported.stderr
        assert (imported_dir / "project.json").is_file()
    print("cli-tests: passed")


if __name__ == "__main__":
    main()

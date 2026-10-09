from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.project import Project
from core.version_info import VersionInfo

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

        hex_result = run_cli("hex", str(FIXTURE), "--type", indexed["type"], "--name", indexed["name"], "--language", str(indexed["language"]), "--length", "8", "--json")
        assert hex_result.returncode == 0, hex_result.stderr
        assert json.loads(hex_result.stdout)["size"] <= 8
        raw_hex = run_cli("hex", str(FIXTURE), "--offset", "0", "--length", "4", "--json")
        assert raw_hex.returncode == 0, raw_hex.stderr
        assert json.loads(raw_hex.stdout)["source"] == "file"
        assert json.loads(raw_hex.stdout)["size"] == 4

        rc_input = temporary_path / "sample.rc"
        rc_input.write_text('STRINGTABLE\nBEGIN\n  1 "Hello"\nEND\n', encoding="utf-8")
        res_output = temporary_path / "sample.res"
        rc_compile = run_cli("rc", "compile", str(rc_input), "--output", str(res_output), "--json")
        assert rc_compile.returncode == 0, rc_compile.stderr
        rc_output = temporary_path / "roundtrip.rc"
        rc_decompile = run_cli("rc", "decompile", str(res_output), "--output", str(rc_output), "--json")
        assert rc_decompile.returncode == 0, rc_decompile.stderr
        assert '1 "Hello"' in rc_output.read_text(encoding="utf-8")

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

        typed_diff = run_cli("diff", str(FIXTURE), str(FIXTURE), "--typed", "--json")
        assert typed_diff.returncode == 0, typed_diff.stderr
        assert json.loads(typed_diff.stdout)["tree"]["status"] == "unchanged"

        project = Project.open_pe(FIXTURE, temporary_path / "project")
        output = temporary_path / "built.dll"
        built = run_cli("build", str(project.project_dir), "--output", str(output), "--json")
        assert built.returncode == 0, built.stderr
        assert output.is_file()
        assert sha256(FIXTURE) == original_hash

        valid = run_cli("validate", str(output), "--strict", "--json")
        assert valid.returncode == 0, valid.stderr
        assert json.loads(valid.stdout)["is_pe"] is True

        malformed = temporary_path / "truncated.dll"
        malformed.write_bytes(FIXTURE.read_bytes()[:512])
        malformed_validate = run_cli("validate", str(malformed), "--json")
        assert malformed_validate.returncode != 0
        malformed_validate_payload = json.loads(malformed_validate.stdout)
        assert malformed_validate_payload["status"] == "MALFORMED_PE"
        malformed_inspect = run_cli("inspect", str(malformed), "--json")
        assert malformed_inspect.returncode != 0
        malformed_inspect_payload = json.loads(malformed_inspect.stdout)
        assert malformed_inspect_payload["analysisStatus"] == "DEGRADED"
        assert malformed_inspect_payload["health"]["status"] == "MALFORMED_PE"

        inspected = run_cli("inspect", str(FIXTURE), "--json")
        assert inspected.returncode == 0, inspected.stderr
        inspected_payload = json.loads(inspected.stdout)
        assert inspected_payload["sections"]
        assert inspected_payload["evidence"]["schema"] == "resource_studio.evidence_summary.v1"
        assert inspected_payload["rawResourceComparison"]["matches"] is True
        assert len(inspected_payload["evidenceHash"]) == 64
        assert "identity" in inspected_payload
        assert inspected_payload["identity"]["schema"] == "resource_studio.pe_identity.v1"
        assert inspected_payload["identity"]["machine"] in {"x64", "x86"}

        image_diff = run_cli("image-diff", str(extracted), str(extracted), "--kind", "bitmap", "--json")
        assert image_diff.returncode == 0, image_diff.stderr
        assert json.loads(image_diff.stdout)["status"] == "unchanged"

        inspect_report = run_cli("report", "inspect", str(FIXTURE), "--format", "json")
        assert inspect_report.returncode == 0, inspect_report.stderr
        assert json.loads(inspect_report.stdout)["imports"]

        diagnostics_report = run_cli("report", "diagnostics", str(FIXTURE), str(FIXTURE), "--format", "json")
        assert diagnostics_report.returncode == 0, diagnostics_report.stderr
        diagnostics_payload = json.loads(diagnostics_report.stdout)
        assert diagnostics_payload["schema"] == "resource_studio.post_write_diagnostics.v1"
        assert diagnostics_payload["protected"]["imports"] is True
        diagnostics_markdown = run_cli("report", "diagnostics", str(FIXTURE), str(FIXTURE), "--format", "markdown")
        assert diagnostics_markdown.returncode == 0, diagnostics_markdown.stderr
        assert "schema" in diagnostics_markdown.stdout

        portable = temporary_path / "portable"
        exported = run_cli("export", str(project.project_dir), "--output", str(portable), "--json")
        assert exported.returncode == 0, exported.stderr
        imported_dir = temporary_path / "imported"
        imported = run_cli("import", str(portable), "--project", str(imported_dir), "--json")
        assert imported.returncode == 0, imported.stderr
        assert (imported_dir / "project.json").is_file()

        # Recipe export test
        from core.pe_writer import LiefPEWriter
        mod_pe = temporary_path / "cli_mod_pe.dll"
        LiefPEWriter().replace_typed_resource(FIXTURE, mod_pe, "MANIFEST", 1, 1033, b"<assembly/>")
        recipe_out = temporary_path / "cli_recipe_out"
        recipe_res = run_cli("recipe", "export", str(FIXTURE), str(mod_pe), "--output", str(recipe_out), "--json")
        assert recipe_res.returncode == 0, recipe_res.stderr
        recipe_payload = json.loads(recipe_res.stdout)
        assert recipe_payload["status"] == "ok"
        assert recipe_payload["operationCount"] == 1
        assert (recipe_out / "recipe.json").is_file()

        # Structured JSON error handling test
        nonexistent = temporary_path / "does_not_exist.dll"
        err_res = run_cli("list", str(nonexistent), "--json")
        assert err_res.returncode == 2
        err_payload = json.loads(err_res.stdout)
        assert err_payload["status"] == "error"
        assert err_payload["exitCode"] == 2
        assert "error" in err_payload

        extract_err = run_cli("extract", str(FIXTURE), "--type", "NONEXISTENT", "--name", "999", "--output", str(temporary_path / "out.bin"), "--json")
        assert extract_err.returncode == 2
        extract_err_payload = json.loads(extract_err.stdout)
        assert extract_err_payload["status"] == "error"
        assert "resource was not found" in extract_err_payload["error"]
    print("cli-tests: passed")


if __name__ == "__main__":
    main()

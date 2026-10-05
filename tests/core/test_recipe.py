from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.batch import BatchWorkspace
from core.diff import diff_resources
from core.pe_writer import LiefPEWriter
from core.recipe import RecipeError, apply_recipe, create_recipe
from core.resource_reader import ResourceReader
from resource_studio_cli import main as cli_main

FIXTURES = ROOT / "tests" / "fixtures"


def main() -> None:
    source_pe = FIXTURES / "sample.dll"

    with tempfile.TemporaryDirectory(prefix="rs-test-recipe-") as temp_dir:
        temp_path = Path(temp_dir)
        edited_pe = temp_path / "edited.dll"
        recipe_dir = temp_path / "exported_recipe"

        # 1. Modify manifest in source_pe to create edited_pe
        writer = LiefPEWriter()
        new_manifest = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
            b'<description>Automated Recipe Test</description>\n'
            b'</assembly>'
        )
        writer.replace_typed_resource(
            source_pe,
            edited_pe,
            "MANIFEST",
            1,
            1033,
            new_manifest,
        )

        # 2. Generate recipe using create_recipe
        result = create_recipe(source_pe, edited_pe, recipe_dir)

        assert result["format"] == "resource_studio.recipe_export.v1"
        assert result["operationCount"] >= 1
        assert result["verified"] is True
        assert (recipe_dir / "recipe.json").is_file()

        manifest = json.loads((recipe_dir / "recipe.json").read_text(encoding="utf-8"))
        assert manifest["format"] == "resource_studio.batch.v1"
        assert len(manifest["jobs"]) == 1
        operations = manifest["jobs"][0]["operations"]
        assert len(operations) >= 1

        step = operations[0]
        assert step["action"] == "replace"
        assert step["type"] == "MANIFEST"
        assert step["name"] == 1
        assert step["language"] == 1033
        assert (recipe_dir / step["dataFile"]).is_file()

        # 3. Apply the generated recipe to a fresh copy of source_pe
        reproduced_pe = temp_path / "reproduced.dll"
        # Update manifest inputs to point to fresh copy
        manifest_copy = json.loads((recipe_dir / "recipe.json").read_text(encoding="utf-8"))
        manifest_copy["jobs"][0]["input"] = str(source_pe)
        manifest_copy["jobs"][0]["output"] = str(reproduced_pe)
        (recipe_dir / "recipe_run.json").write_text(json.dumps(manifest_copy, indent=2), encoding="utf-8")

        workspace = BatchWorkspace.load(recipe_dir / "recipe_run.json")
        result = workspace.apply()
        assert len(result["jobs"]) == 1
        assert result["jobs"][0]["operations"][0]["verified"] is True
        assert reproduced_pe.is_file()

        # 4. Verify reproduced_pe has zero diff against edited_pe
        diff_result = diff_resources(
            ResourceReader(edited_pe).entries,
            ResourceReader(reproduced_pe).entries,
        )
        assert diff_result.status == "unchanged"

        # 5. Test CLI recipe export subcommand
        cli_recipe_dir = temp_path / "cli_recipe"
        exit_code = cli_main([
            "recipe",
            "export",
            str(source_pe),
            str(edited_pe),
            "--output",
            str(cli_recipe_dir),
            "--json",
        ])
        assert exit_code == 0
        assert (cli_recipe_dir / "recipe.json").is_file()

        # 6. Test RecipeError on non-existent original or edited file
        try:
            create_recipe(temp_path / "non_existent.dll", edited_pe, temp_path / "err_recipe")
            assert False, "Should have raised RecipeError for missing original"
        except RecipeError:
            pass

        # 7. Test recipe generation for identical files raises RecipeError
        unchanged_dir = temp_path / "unchanged_recipe"
        try:
            create_recipe(source_pe, source_pe, unchanged_dir)
            assert False, "Should have raised RecipeError for identical files"
        except RecipeError as exc:
            assert "No changes detected" in str(exc)

        # 8. Test apply_recipe Python API
        patched_pe = temp_path / "patched.dll"
        apply_res = apply_recipe(source_pe, recipe_dir / "recipe.json", patched_pe)
        assert apply_res["status"] == "ok"
        assert patched_pe.is_file()
        applied_diff = diff_resources(ResourceReader(patched_pe).entries, ResourceReader(edited_pe).entries)
        assert applied_diff.status == "unchanged"

        # 9. Test CLI recipe apply subcommand
        cli_patched_pe = temp_path / "cli_patched.dll"
        exit_code_apply = cli_main([
            "recipe",
            "apply",
            str(source_pe),
            str(cli_recipe_dir / "recipe.json"),
            "--output",
            str(cli_patched_pe),
            "--json",
        ])
        assert exit_code_apply == 0
        assert cli_patched_pe.is_file()
        cli_applied_diff = diff_resources(ResourceReader(cli_patched_pe).entries, ResourceReader(edited_pe).entries)
        assert cli_applied_diff.status == "unchanged"

    print("test_recipe passed")


if __name__ == "__main__":
    main()

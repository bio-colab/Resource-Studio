from __future__ import annotations

import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .batch import BatchWorkspace
from .diff import diff_resources
from .resource_reader import ResourceReader


class RecipeError(ValueError):
    pass


_SAFE_CHARS = re.compile(r"[^A-Za-z0-9_-]")


def _safe_filename(text: str) -> str:
    return _SAFE_CHARS.sub("_", text)


def create_recipe(
    original_path: Path,
    edited_path: Path,
    output_dir: Path,
    *,
    output_filename: str = "recipe.json",
    sample_input_name: str | None = None,
    sample_output_name: str | None = None,
) -> dict[str, Any]:
    original_path = Path(original_path).expanduser().resolve()
    edited_path = Path(edited_path).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()

    if not original_path.is_file():
        raise RecipeError(f"original PE not found: {original_path}")
    if not edited_path.is_file():
        raise RecipeError(f"edited PE not found: {edited_path}")

    orig_entries = ResourceReader(original_path).entries
    edit_entries = ResourceReader(edited_path).entries

    tree = diff_resources(orig_entries, edit_entries)
    if tree.status == "unchanged":
        raise RecipeError("No changes detected between the two PE files.")

    orig_map = {e.key: e for e in orig_entries}
    edit_map = {e.key: e for e in edit_entries}

    deletes: list[dict[str, Any]] = []
    replaces: list[tuple[dict[str, Any], bytes]] = []
    adds: list[tuple[dict[str, Any], bytes]] = []

    for node in tree.children:
        if node.status == "unchanged":
            continue
        key_parts = node.key.split(":")
        rtype = key_parts[0]
        rname = key_parts[1]
        rlang = int(key_parts[2]) if key_parts[2] != "None" else 0
        name_val = int(rname) if rname.isdigit() else rname
        entry_key = (rtype, rname, int(key_parts[2]) if key_parts[2] != "None" else None)

        if node.status == "removed":
            deletes.append({
                "action": "delete",
                "type": rtype,
                "name": name_val,
                "language": rlang,
            })
        elif node.status == "added":
            if not isinstance(name_val, int):
                raise RecipeError(f"Cannot generate recipe: added resource '{rname}' has a non-numeric name, which is not supported by batch manifests.")
            entry = edit_map[entry_key]
            rel_file = f"payloads/{_safe_filename(rtype)}_{_safe_filename(str(rname))}_{rlang}.bin"
            adds.append(({
                "action": "add",
                "type": rtype,
                "name": name_val,
                "language": rlang,
                "dataFile": rel_file,
            }, entry.data))
        elif node.status == "modified":
            entry = edit_map[entry_key]
            rel_file = f"payloads/{_safe_filename(rtype)}_{_safe_filename(str(rname))}_{rlang}.bin"
            replaces.append(({
                "action": "replace",
                "type": rtype,
                "name": name_val,
                "language": rlang,
                "dataFile": rel_file,
            }, entry.data))

    all_ops: list[dict[str, Any]] = []
    all_payloads: list[tuple[str, bytes]] = []

    for op in deletes:
        all_ops.append(op)
    for op, data in replaces:
        all_ops.append(op)
        all_payloads.append((op["dataFile"], data))
    for op, data in adds:
        all_ops.append(op)
        all_payloads.append((op["dataFile"], data))

    in_name = sample_input_name or original_path.name
    out_name = sample_output_name or f"modified_{original_path.name}"
    manifest_doc = {
        "format": "resource_studio.batch.v1",
        "description": f"Automation recipe derived from changes between {original_path.name} and {edited_path.name}",
        "jobs": [
            {
                "input": in_name,
                "output": out_name,
                "operations": all_ops,
            }
        ],
    }

    # Pre-verification: apply recipe in a temporary workspace to confirm it recreates edited_path exactly
    with tempfile.TemporaryDirectory(prefix="resource-studio-recipe-verify-") as temp_dir:
        temp_path = Path(temp_dir)
        temp_orig = temp_path / in_name
        temp_out = temp_path / out_name
        shutil.copy2(original_path, temp_orig)

        temp_manifest_doc = dict(manifest_doc)
        temp_manifest_doc["jobs"] = [
            {
                "input": str(temp_orig),
                "output": str(temp_out),
                "operations": all_ops,
            }
        ]
        for rel_file, data in all_payloads:
            p = temp_path / rel_file
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

        temp_manifest_file = temp_path / "test_recipe.json"
        temp_manifest_file.write_text(json.dumps(temp_manifest_doc, indent=2), encoding="utf-8")

        ws = BatchWorkspace.load(temp_manifest_file)
        apply_res = ws.apply()

        # Check roundtrip equality
        applied_entries = ResourceReader(temp_out).entries
        verify_diff = diff_resources(applied_entries, edit_entries)
        if verify_diff.status != "unchanged":
            raise RecipeError("Recipe verification failed: applied output does not reproduce all resource modifications.")

    # Verification passed! Write real artifacts to output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    payloads_dir = output_dir / "payloads"
    payloads_dir.mkdir(parents=True, exist_ok=True)

    for rel_file, data in all_payloads:
        target = output_dir / rel_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    manifest_file = output_dir / output_filename
    manifest_file.write_text(json.dumps(manifest_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return {
        "format": "resource_studio.recipe_export.v1",
        "recipeFile": str(manifest_file),
        "outputDir": str(output_dir),
        "operationCount": len(all_ops),
        "payloadCount": len(all_payloads),
        "operations": all_ops,
        "verified": True,
    }


def apply_recipe(
    target_path: Path,
    recipe_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    target_path = Path(target_path).expanduser().resolve()
    recipe_path = Path(recipe_path).expanduser().resolve()
    output_path = Path(output_path).expanduser().resolve()

    if not target_path.is_file():
        raise RecipeError(f"target PE file not found: {target_path}")

    recipe_file = recipe_path if recipe_path.is_file() else recipe_path / "recipe.json"
    if not recipe_file.is_file():
        raise RecipeError(f"recipe manifest not found: {recipe_file}")

    recipe_dir = recipe_file.parent

    try:
        manifest_data = json.loads(recipe_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RecipeError(f"failed to read recipe JSON: {exc}") from exc

    if manifest_data.get("format") != "resource_studio.batch.v1":
        raise RecipeError(f"unsupported recipe format: {manifest_data.get('format')}")

    jobs = manifest_data.get("jobs", [])
    if not jobs or not isinstance(jobs, list):
        raise RecipeError("recipe manifest has no jobs")

    job = jobs[0]
    operations = job.get("operations", [])
    if not operations:
        raise RecipeError("recipe has no operations to apply")

    adjusted_ops = []
    for op in operations:
        adjusted_op = dict(op)
        if "dataFile" in adjusted_op:
            df = recipe_dir / adjusted_op["dataFile"]
            if not df.is_file():
                raise RecipeError(f"recipe payload not found: {df}")
            adjusted_op["dataFile"] = str(df.resolve())
        adjusted_ops.append(adjusted_op)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="resource-studio-recipe-apply-") as temp_dir:
        temp_manifest = Path(temp_dir) / "apply_manifest.json"
        manifest_doc = {
            "format": "resource_studio.batch.v1",
            "jobs": [
                {
                    "input": str(target_path),
                    "output": str(output_path),
                    "operations": adjusted_ops,
                }
            ],
        }
        temp_manifest.write_text(json.dumps(manifest_doc, indent=2), encoding="utf-8")
        ws = BatchWorkspace.load(temp_manifest)
        report = ws.apply()

    return {
        "status": "ok",
        "target": str(target_path),
        "output": str(output_path),
        "operationsApplied": len(adjusted_ops),
        "report": report,
    }

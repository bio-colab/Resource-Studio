from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.resource_reader import ResourceReader
from core.pe_inspector import PEInspector

TARGETS = [
    Path("C:/Program Files/7-Zip/7zFM.exe"),
    Path("C:/Windows/System32/charmap.exe"),
    Path("C:/Windows/System32/en-US/charmap.exe.mui"),
    Path("C:/Windows/System32/winver.exe"),
]

TYPE_MAP = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    9: "ACCELERATORS",
    10: "RCDATA",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    24: "MANIFEST",
    222: "MUI",
}


def run_rea_pe_resources(target: Path) -> list[dict]:
    # Use rea CLI via shell
    cmd = f'rea inspect-pe-resources "{target}" --json'
    res = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    data = json.loads(res.stdout)
    res_obj = data.get("raw_result") or data.get("normalized_result") or {}
    if isinstance(res_obj, dict) and "resources" in res_obj:
        return res_obj["resources"]
    if "resources" in data:
        return data["resources"]
    return []


def verify_target(target: Path) -> dict:
    if not target.is_file():
        return {"target": str(target), "status": "SKIPPED_NOT_FOUND"}

    reader = ResourceReader(target)
    rs_entries = {
        (str(e.resource_type).upper(), str(e.name).upper(), e.language): e
        for e in reader.entries
    }

    rea_resources = run_rea_pe_resources(target)

    mismatches = []
    matches_count = 0

    for item in rea_resources:
        t_raw = item["type"]
        t_id = t_raw.get("id") if t_raw.get("kind") == "id" else t_raw.get("name")
        t_str = TYPE_MAP.get(t_id, str(t_id)).upper()

        n_raw = item["name"]
        n_str = str(n_raw.get("id") if n_raw.get("kind") == "id" else n_raw.get("name")).upper()

        l_raw = item["language"]
        lang = l_raw.get("id") if l_raw.get("kind") == "id" else 0

        rea_size = item["payload"]["location"]["bytes"]
        rea_sha = item["payload"]["sha256"]

        rs_match = rs_entries.get((t_str, n_str, lang))
        if not rs_match:
            cands = [e for k, e in rs_entries.items() if k[0] == t_str and k[1] == n_str]
            if cands:
                rs_match = cands[0]

        if not rs_match:
            mismatches.append(f"Missing in ResourceStudio: {t_str}/{n_str} (lang {lang})")
        else:
            if len(rs_match.data) != rea_size:
                mismatches.append(
                    f"Size mismatch in {t_str}/{n_str}: RS={len(rs_match.data)} vs REA={rea_size}"
                )
            elif rs_match.sha256.lower() != rea_sha.lower():
                mismatches.append(
                    f"SHA256 mismatch in {t_str}/{n_str}: RS={rs_match.sha256[:10]} vs REA={rea_sha[:10]}"
                )
            else:
                matches_count += 1

    return {
        "target": target.name,
        "resourceStudioCount": len(rs_entries),
        "reaCount": len(rea_resources),
        "perfectMatches": matches_count,
        "mismatches": mismatches,
        "status": "PASS" if not mismatches and matches_count == len(rea_resources) else "FAIL",
    }


def main() -> int:
    all_passed = True
    print("=== Phase 1: PE Structure & Raw Resource Alignment Differential Test ===")
    for target in TARGETS:
        if not target.is_file():
            continue
        res = verify_target(target)
        print(f"\nTarget: {res['target']}")
        print(f"  ResourceStudio entries: {res['resourceStudioCount']}")
        print(f"  REA resources:          {res['reaCount']}")
        print(f"  Perfect matches:        {res['perfectMatches']}")
        if res["mismatches"]:
            print(f"  Mismatches ({len(res['mismatches'])}):")
            for m in res["mismatches"]:
                print(f"    - {m}")
            all_passed = False
        else:
            print("  Status: 100% BYTE-FOR-BYTE & SHA256 CONCORDANCE")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.health import PEHealth
from core.project import Project

TARGETS = [
    Path("C:/Program Files/7-Zip/7zFM.exe"),
    Path("C:/Windows/System32/charmap.exe"),
    Path("C:/Windows/System32/en-US/charmap.exe.mui"),
    Path("C:/Windows/System32/winver.exe"),
]


def verify_saveas_preservation(target: Path) -> dict:
    if not target.is_file():
        return {"target": str(target), "status": "SKIPPED_NOT_FOUND"}

    with tempfile.TemporaryDirectory(prefix="rs-phase5-conformance-") as td:
        proj_dir = Path(td) / "project"
        build_output = Path(td) / f"built_{target.name}"

        project = Project.open_pe(target, proj_dir)
        built_path = project.build(build_output)

        orig_bytes = target.read_bytes()
        built_bytes = built_path.read_bytes()

        byte_identity = orig_bytes == built_bytes
        health = PEHealth.inspect(built_path)

        issues = []
        if not byte_identity:
            issues.append(f"Byte difference detected: original {len(orig_bytes)} vs built {len(built_bytes)}")
        if not health.is_pe:
            issues.append("Built binary is not recognized as a valid PE")
        if health.status != "VALID_PE":
            issues.append(f"PE health status is {health.status}: {health.warnings}")

        return {
            "target": target.name,
            "resourceCount": len(project.entries),
            "byteIdentity": byte_identity,
            "healthStatus": health.status,
            "issues": issues,
            "status": "PASS" if not issues else "FAIL",
        }


def main() -> int:
    all_passed = True
    print("=== Phase 5: Differential Save-As & Binary Preservation Conformance Test ===")
    for target in TARGETS:
        if not target.is_file():
            continue
        res = verify_saveas_preservation(target)
        print(f"\nTarget: {res['target']}")
        print(f"  Resources verified:  {res['resourceCount']}")
        print(f"  Byte identity match: {res['byteIdentity']}")
        print(f"  Health status:       {res['healthStatus']}")
        if res["issues"]:
            print(f"  Issues ({len(res['issues'])}):")
            for issue in res["issues"]:
                print(f"    - {issue}")
            all_passed = False
        else:
            print("  Status: 100% BYTE-PRESERVED & INVARIANTS INTACT")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

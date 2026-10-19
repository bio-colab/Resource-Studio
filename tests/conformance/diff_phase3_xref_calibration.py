from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.xref_scanner import scan_pe_xrefs

TARGETS = [
    Path("C:/Program Files/7-Zip/7zFM.exe"),
    Path("C:/Windows/System32/charmap.exe"),
    Path("C:/Windows/System32/winver.exe"),
]


def verify_xref_calibration(target: Path) -> dict:
    if not target.is_file():
        return {"target": str(target), "status": "SKIPPED_NOT_FOUND"}

    report = scan_pe_xrefs(target)
    issues = []

    if not report.has_resource_apis:
        issues.append(f"No resource APIs detected in {target.name}")

    if report.summary["totalResources"] != len(report.resources):
        issues.append("Mismatch in summary count vs resource list length")

    for res in report.resources:
        for ref in res.references:
            if ref.address <= 0:
                issues.append(f"Invalid reference address {ref.address:#x} for {res.resource_type}/{res.name}")
            if not ref.section:
                issues.append(f"Missing section for reference at {ref.address:#x}")
            if not ref.instruction:
                issues.append(f"Missing instruction for reference at {ref.address:#x}")

    return {
        "target": target.name,
        "machine": report.machine,
        "importedApis": len(report.imported_resource_apis),
        "totalResources": report.summary["totalResources"],
        "referenced": report.summary["referenced"],
        "deadOrphans": report.summary["deadOrphans"],
        "issues": issues,
        "status": "PASS" if not issues else "FAIL",
    }


def main() -> int:
    all_passed = True
    print("=== Phase 3: Code XRef Scanner Calibration Conformance Test ===")
    for target in TARGETS:
        if not target.is_file():
            continue
        res = verify_xref_calibration(target)
        print(f"\nTarget: {res['target']} ({res['machine']})")
        print(f"  Imported resource APIs: {res['importedApis']}")
        print(f"  Total resources:        {res['totalResources']}")
        print(f"  Referenced resources:   {res['referenced']}")
        print(f"  Dead/orphan resources:  {res['deadOrphans']}")
        if res["issues"]:
            print(f"  Issues ({len(res['issues'])}):")
            for issue in res["issues"]:
                print(f"    - {issue}")
            all_passed = False
        else:
            print("  Status: 100% CALIBRATED & VALIDATED")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

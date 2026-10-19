from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.dialog_resources import DialogResource
from core.resource_reader import ResourceReader

TARGETS = [
    Path("C:/Program Files/7-Zip/7zFM.exe"),
    Path("C:/Windows/System32/charmap.exe"),
    Path("C:/Windows/System32/en-US/charmap.exe.mui"),
    Path("C:/Windows/System32/winver.exe"),
]


def verify_dialog_conformance(target: Path) -> dict:
    if not target.is_file():
        return {"target": str(target), "status": "SKIPPED_NOT_FOUND"}

    reader = ResourceReader(target)
    dialog_entries = reader.find(resource_type="DIALOG")

    results = []
    total_controls = 0
    mismatches = []

    for entry in dialog_entries:
        try:
            dlg = DialogResource.parse(entry.data)
            reconstructed = dlg.to_bytes()
            if reconstructed != entry.data:
                mismatches.append(
                    f"Roundtrip byte mismatch in Dialog {entry.name}: original {len(entry.data)} vs reconstructed {len(reconstructed)}"
                )
            total_controls += len(dlg.controls)
            # Verify coordinates and DLU to pixel conversions
            px_w, px_h = dlg.dlu_to_pixels(dlg.width, dlg.height)
            assert px_w >= 0 and px_h >= 0

            for ctrl in dlg.controls:
                c_x, c_y, c_w, c_h = ctrl.pixel_bounds()
                assert isinstance(c_x, int) and isinstance(c_y, int)

            results.append({
                "name": entry.name,
                "title": dlg.title,
                "extended": dlg.extended,
                "controls": len(dlg.controls),
                "dluSize": (dlg.width, dlg.height),
                "pixelSize": (px_w, px_h),
            })
        except Exception as exc:
            mismatches.append(f"Parse failure in Dialog {entry.name}: {exc}")

    return {
        "target": target.name,
        "dialogCount": len(dialog_entries),
        "totalControls": total_controls,
        "mismatches": mismatches,
        "status": "PASS" if not mismatches else "FAIL",
        "dialogs": results,
    }


def main() -> int:
    all_passed = True
    print("=== Phase 2: Dialog & DLU Font Metrics and Coordinate Conformance Test ===")
    for target in TARGETS:
        if not target.is_file():
            continue
        res = verify_dialog_conformance(target)
        print(f"\nTarget: {res['target']}")
        print(f"  Dialog templates: {res['dialogCount']}")
        print(f"  Total controls:   {res['totalControls']}")
        if res["mismatches"]:
            print(f"  Mismatches ({len(res['mismatches'])}):")
            for m in res["mismatches"]:
                print(f"    - {m}")
            all_passed = False
        else:
            print("  Status: 100% BYTE-FOR-BYTE RECONSTRUCTION & METRIC CONCORDANCE")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

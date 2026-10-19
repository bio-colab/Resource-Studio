from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

PHASES = [
    ("Phase 1: PE Structure & Raw Resource Alignment", ROOT / "diff_phase1_pe_alignment.py"),
    ("Phase 2: Dialog & DLU Font Metrics and Coordinate Conformance", ROOT / "diff_phase2_dialog_dlu.py"),
    ("Phase 3: Code XRef Scanner Calibration Conformance", ROOT / "diff_phase3_xref_calibration.py"),
    ("Phase 4: Resource-to-Behavior Graph Conformance", ROOT / "diff_phase4_behavioral_graph.py"),
    ("Phase 5: Differential Save-As & Binary Preservation Conformance", ROOT / "diff_phase5_saveas_preservation.py"),
]


def main() -> int:
    print("================================================================================")
    print("       RESOURCE STUDIO - FULL REA EMPIRICAL HARDENING & CONFORMANCE SUITE       ")
    print("================================================================================")
    failed = []
    for title, script in PHASES:
        print(f"\n--- Running {title} ---")
        res = subprocess.run([sys.executable, str(script)], check=False)
        if res.returncode != 0:
            failed.append(title)

    print("\n" + "=" * 80)
    if not failed:
        print("ALL 5 EMPIRICAL CONFORMANCE PHASES PASSED WITH 100% CONCORDANCE AGAINST REA!")
        print("=" * 80)
        return 0
    else:
        print(f"FAILED PHASES ({len(failed)}):")
        for f in failed:
            print(f"  - {f}")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())

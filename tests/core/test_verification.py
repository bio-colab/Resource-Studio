from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

import lief

from core.fuzz_harness import assert_no_unexpected_failures, run_structure_aware_cases, structure_aware_cases
from core.pe_writer import LiefPEWriter
from core.verification import ResourceGraph, semantic_fingerprint


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    original_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    before = ResourceGraph.from_path(FIXTURE)
    assert before.leaves
    assert len(before.fingerprint) == 64
    assert len(before.layout_fingerprint) == 64
    assert semantic_fingerprint("RCDATA", b"same") == semantic_fingerprint("RCDATA", b"same")

    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "verified.dll"
        result = LiefPEWriter().add_resource(FIXTURE, output, "RCDATA", 1901, 1033, b"verification")
        assert result.verified
        assert result.verification is not None
        report = result.verification
        assert report["passed"] is True
        assert report["verified"] is (os.name == "nt")
        assert report["platformLimited"] is (os.name != "nt")
        assert [phase["name"] for phase in report["phases"]] == [
            "PLAN", "MUTATE", "SERIALIZE", "REOPEN", "STRUCTURAL_VALIDATION",
            "RESOURCE_GRAPH_VALIDATION", "SEMANTIC_DIFF", "PRESERVATION_CHECK",
            "WINDOWS_VALIDATION", "AUTHENTICODE_VERIFICATION", "COMMIT", "AUDIT",
        ]
        assert report["targetChanged"] is True
        assert report["resourceRoundTrip"] is True
        assert all(report["preservation"].values())
        assert report["integrity"]

        def parse_case(data: bytes) -> None:
            with tempfile.NamedTemporaryFile(suffix=".dll") as handle:
                handle.write(data)
                handle.flush()
                parsed = lief.parse(handle.name)
                if parsed is None:
                    raise ValueError("LIEF rejected input")

        cases = structure_aware_cases(FIXTURE.read_bytes(), max_cases=12)
        assert len(cases) >= 2
        outcomes = run_structure_aware_cases("pe-parser", parse_case, FIXTURE.read_bytes(), max_cases=12)
        assert len(outcomes) == len(cases)
        assert_no_unexpected_failures(outcomes)

    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == original_hash
    print("verification-engine-tests: passed")


if __name__ == "__main__":
    main()

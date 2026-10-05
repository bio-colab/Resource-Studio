from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from core.forensics import ForensicEvidence, ForensicBaseline, verify_transformation
from core.project import Project


ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def test_forensic_language_none_is_a_target_wildcard() -> None:
    baseline = ForensicBaseline.from_path(FIXTURE)
    leaf = baseline.resource_graph["leaves"][0]
    with tempfile.TemporaryDirectory(prefix="resource-studio-forensic-regression-") as directory:
        candidate = Path(directory) / FIXTURE.name
        candidate.write_bytes(FIXTURE.read_bytes())
        evidence = verify_transformation(
            FIXTURE,
            candidate,
            resource_type=leaf["type"],
            resource_name=leaf["name"],
            language=None,
            operation="replace",
            operation_id="language-none-regression",
        )
        semantic_diff = {"changed": [[leaf["type"], leaf["name"], leaf["language"]]], "added": [], "removed": []}
        evidence = replace(evidence, verification=replace(evidence.verification, semantic_diff=semantic_diff))
        difference = evidence.to_dict()["forensicDifference"]
    assert difference["targeted"]["changed"] is True
    assert difference["resourceTree"]["unintendedChanges"] == 0
    assert ForensicEvidence._target_key_matches([leaf["type"], leaf["name"], leaf["language"]], [leaf["type"], leaf["name"], None])


def test_stale_project_lock_is_reclaimed() -> None:
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    with tempfile.TemporaryDirectory(prefix="resource-studio-lock-regression-") as directory:
        project = Project(Path(directory) / "project")
        project.project_dir.mkdir(parents=True)
        project.lock_file.write_text(json.dumps({"pid": process.pid, "project": str(project.project_dir)}) + "\n", encoding="utf-8")
        assert project.acquire_lock() == project.lock_file
        assert json.loads(project.lock_file.read_text(encoding="utf-8"))["pid"] == os.getpid()
        project.release_lock()


def main() -> None:
    test_forensic_language_none_is_a_target_wildcard()
    test_stale_project_lock_is_reclaimed()
    print("project-lock-and-forensic-regressions: passed")


if __name__ == "__main__":
    main()

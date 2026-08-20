from __future__ import annotations

import hashlib
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from core.pe_writer import LiefPEWriter, PEWriterError


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "existing.dll"
        output.write_bytes(b"previous-output")
        before = output.read_bytes()
        with patch("core.durable_commit.commit_temporary", side_effect=OSError("simulated commit crash")):
            try:
                LiefPEWriter().add_resource(FIXTURE, output, "RCDATA", 2901, 1033, b"crash-consistency")
            except PEWriterError:
                pass
            else:
                raise AssertionError("simulated commit crash was not propagated")
        assert output.read_bytes() == before
        assert not list(Path(temporary).glob("resource-studio-rollback-*"))
        assert hashlib.sha256(output.read_bytes()).hexdigest() == hashlib.sha256(before).hexdigest()

        output.write_bytes(b"previous-output-again")
        before = output.read_bytes()
        from core import verification as verification_module

        original_verify = verification_module.verify_candidate

        def fail_after_commit(*args, **kwargs):
            report = original_verify(*args, **kwargs)
            if kwargs.get("committed"):
                return replace(report, passed=False, errors=("simulated post-commit verification failure",))
            return report

        with patch("core.verification.verify_candidate", side_effect=fail_after_commit):
            try:
                LiefPEWriter().add_resource(FIXTURE, output, "RCDATA", 2902, 1033, b"post-commit-failure")
            except PEWriterError:
                pass
            else:
                raise AssertionError("post-commit verification failure was not propagated")
        assert output.read_bytes() == before
        assert not list(Path(temporary).glob("resource-studio-rollback-*"))
    print("crash-consistency-tests: passed")


if __name__ == "__main__":
    main()

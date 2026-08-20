from __future__ import annotations

import os
import tempfile
from pathlib import Path

from core.signature import SignatureToolError, find_signtool, inspect_signature, resign_authenticode, strip_authenticode

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    report = inspect_signature(FIXTURE)
    assert report.present is False
    before = FIXTURE.read_bytes()
    with tempfile.TemporaryDirectory(prefix="resource-studio-signature-test-") as temp:
        output = Path(temp) / "unsigned-stripped.dll"
        try:
            strip_authenticode(FIXTURE, output)
        except SignatureToolError as exc:
            assert "not signed" in str(exc)
        else:
            raise AssertionError("unsigned strip must fail closed")
        assert not output.exists()
        assert FIXTURE.read_bytes() == before

        try:
            resign_authenticode(FIXTURE, output, Path(temp) / "missing.pfx", password_env="RS_TEST_PFX_PASSWORD")
        except SignatureToolError as exc:
            if os.name == "nt":
                assert "Windows SDK" in str(exc) or "PFX" in str(exc) or "password" in str(exc)
            else:
                assert "Windows only" in str(exc)
        else:
            raise AssertionError("re-sign must not run without Windows signing prerequisites")
        assert not output.exists()
        assert FIXTURE.read_bytes() == before

        try:
            find_signtool(Path(temp) / "missing-signtool.exe")
        except SignatureToolError as exc:
            assert "signtool" in str(exc).lower()
        else:
            raise AssertionError("missing explicit signtool path must fail")
    print("signature-operation-tests: passed")


if __name__ == "__main__":
    main()

import shutil
import tempfile
from pathlib import Path

from core.diagnostics import build_post_write_diagnostics
from core.pe_writer import LiefPEWriter


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    original = FIXTURE.read_bytes()
    with tempfile.TemporaryDirectory(prefix="resource-studio-diagnostics-") as temporary:
        root = Path(temporary)
        before = root / "before.dll"
        after = root / "after.dll"
        shutil.copy2(FIXTURE, before)
        LiefPEWriter().replace_resource(before, after, "MANIFEST", 1, 1033, b"<assembly></assembly>")
        report = build_post_write_diagnostics(before, after)
        assert report["schema"] == "resource_studio.post_write_diagnostics.v1"
        assert report["before"]["sha256"] != report["after"]["sha256"]
        assert report["resources"]["changedCount"] >= 1
        assert report["protected"]["imports"] is True
        assert report["protected"]["overlay"] is True
        assert report["rawResourceComparison"]["matches"] is True
        assert report["evidence"]["schema"] == "resource_studio.evidence_summary.v1"
    assert FIXTURE.read_bytes() == original
    print("diagnostics-tests: passed")


if __name__ == "__main__":
    main()

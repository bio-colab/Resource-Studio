import hashlib
import os
from pathlib import Path
import shutil
import tempfile

from core.forensics import ForensicBaseline, verify_transformation
from core.provenance import canonical_json


def main() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "sample.dll"
    baseline = ForensicBaseline.from_path(fixture)
    payload = baseline.to_dict()
    assert payload["schema"] == "resource_studio.forensic_baseline.v1"
    assert len(payload["sha256"]) == 64
    assert payload["size"] == fixture.stat().st_size
    assert payload["pe"]["machine"]
    assert payload["resourceGraph"]["leafCount"] >= 0
    assert "fingerprint" in payload["resourceGraph"]
    assert "valid" in payload["deepInvariants"]
    assert "storedChecksum" in payload["integrity"]
    assert "signatureVerification" in payload["integrity"]
    assert payload["sha256"] == ForensicBaseline.from_path(fixture).sha256
    with tempfile.TemporaryDirectory(prefix="resource-studio-baseline-") as directory:
        artifact = Path(directory) / "baseline.json"
        assert baseline.save(artifact) == artifact.resolve()
        loaded = ForensicBaseline.load(artifact)
        assert loaded.to_dict() == payload
    leaf = payload["resourceGraph"]["leaves"][0]
    with tempfile.TemporaryDirectory(prefix="resource-studio-forensic-") as directory:
        candidate = Path(directory) / fixture.name
        shutil.copy2(fixture, candidate)
        evidence = verify_transformation(
            fixture,
            candidate,
            resource_type=leaf["type"],
            resource_name=leaf["name"],
            language=leaf["language"],
            operation="replace",
            operation_id="test-no-op-1",
        ).to_dict()
        diff = evidence["forensicDifference"]
        assert evidence["operationId"] == "test-no-op-1"
        assert diff["targeted"]["changed"] is False
        assert diff["resourceTree"]["unintendedChanges"] == 0
        assert diff["passed"] is True
        assert diff["pureLoader"]["status"] == "FOUND"
        assert diff["pureLoader"]["selectedLanguage"] == leaf["language"]
        assert evidence["evidenceSummary"]["schema"] == "resource_studio.evidence_summary.v1"
        assert evidence["evidenceSummary"]["corroboration"]["resourceGraphVsRaw"] == "CORROBORATED"
        assert evidence["verification"]["verified"] is (os.name == "nt")
        assert evidence["verification"]["platformLimited"] is (os.name != "nt")
        assert evidence["chain"]["prevSha256"] is None
        assert evidence["chain"]["envFingerprint"]["sha256"]
        assert isinstance(evidence["chain"]["commandLine"], list)
        unsigned = dict(evidence)
        unsigned.pop("sha256")
        assert evidence["sha256"] == hashlib.sha256(canonical_json(unsigned)).hexdigest()
    print("forensic-baseline-tests: passed")


if __name__ == "__main__":
    main()

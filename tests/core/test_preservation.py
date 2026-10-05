from pathlib import Path
import shutil
import tempfile

from core.forensics import ForensicBaseline
from core.preservation import build_preservation_map


def main() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "sample.dll"
    leaf = ForensicBaseline.from_path(fixture).resource_graph["leaves"][0]
    with tempfile.TemporaryDirectory(prefix="resource-studio-preservation-") as directory:
        output = Path(directory) / fixture.name
        shutil.copy2(fixture, output)
        data = bytearray(output.read_bytes())
        data[0x400] ^= 0xFF
        output.write_bytes(data)
        report = build_preservation_map(
            fixture,
            output,
            resource_type=leaf["type"],
            resource_name=leaf["name"],
            language=leaf["language"],
        )
        assert report.passed is False
        assert report.unexpected
        assert report.unexpected[0].category == "UNEXPECTED"
    print("preservation-map-tests: passed")


if __name__ == "__main__":
    main()

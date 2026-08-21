from pathlib import Path

from core.static_code_analysis import analyze_static_code


ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    report = analyze_static_code(FIXTURE, max_bytes=4096, max_instructions=5000)
    assert report["schema"] == "resource_studio.static_code_analysis.v1"
    assert report["source"]["sha256"]
    assert report["status"] in {"ANALYZED", "DECODER_UNAVAILABLE", "UNSUPPORTED_ARCH", "NO_CODE_DECODED"}
    if report["status"] == "ANALYZED":
        assert report["entrypoint"]["rva"] > 0
        assert report["disassembly"]["instructionCount"] <= 5000
        assert report["disassembly"]["instructions"]
        assert report["cfg"]["nodes"]
        assert all(node["startRva"] < node["endRva"] for node in report["cfg"]["nodes"])
        assert all(edge["from"].startswith("B") and edge["to"].startswith("B") for edge in report["cfg"]["edges"])
    print("static-code-analysis-tests: passed")


if __name__ == "__main__":
    main()

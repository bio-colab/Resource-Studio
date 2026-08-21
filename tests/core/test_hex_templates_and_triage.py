from __future__ import annotations

from core.evidence_triage import build_triage_map
from core.hex_templates import build_hex_template


def main() -> None:
    dib = (40).to_bytes(4, "little") + (640).to_bytes(4, "little", signed=True) + (480).to_bytes(4, "little", signed=True) + (1).to_bytes(2, "little") + (32).to_bytes(2, "little") + bytes(24)
    template = build_hex_template("BITMAP", dib)
    assert template["schema"] == "resource_studio.hex_template.v1"
    assert template["template"] == "BITMAPINFOHEADER"
    fields = {field["name"]: field for field in template["fields"]}
    assert fields["biWidth"]["offset"] == 4 and fields["biWidth"]["length"] == 4 and fields["biWidth"]["value"] == 640
    assert fields["biWidth"]["hex"] == "80 02 00 00"

    report = {
        "parse": {"status": "VALID_PE"},
        "evidence": {"observations": [{"subject": "resource:ICON/1/1033", "confidence": "LOW"}]},
        "findings": [{"severity": "MEDIUM", "confidence": "LOW", "category": "CORRUPTION", "title": "Resource discrepancy"}],
        "staticIndicators": [{"category": "OBFUSCATION", "kind": "HIGH_ENTROPY_SECTION", "section": ".text", "confidence": "LIMITED"}],
        "unpackingIndicators": [],
    }
    triage = build_triage_map(report)
    assert triage["schema"] == "resource_studio.evidence_triage.v1"
    assert triage["global"]["level"] == "HIGH"
    assert triage["resources"]["resource:ICON/1/1033"]["level"] == "HIGH"
    assert triage["resources"]["resource:ICON/1/1033"]["color"] == "#DC2626"
    assert "visual triage" in " ".join(triage["limitations"]).lower() and "verdict" in " ".join(triage["limitations"]).lower()
    print("hex-template-and-triage-tests: passed")


if __name__ == "__main__":
    main()

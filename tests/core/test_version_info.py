from __future__ import annotations

from core.version_info import VersionInfo


def main() -> None:
    info = VersionInfo(file_version="1.2.3.4", product_version="2.0.0.0")
    info.set_string("FileDescription", "Resource Studio")
    info.set_translation(1025)
    info.set_translation(1033)
    assert info.validate()["valid"] is True
    restored = VersionInfo.from_json(info.to_json())
    assert restored.file_version == "1.2.3.4"
    assert restored.translations == [1025, 1033]

    invalid = VersionInfo(file_version="1.2", product_version="x")
    assert invalid.validate()["valid"] is False

    rc_source = VersionInfo(
        file_version="1.2.3.4",
        product_version="4.3.2.1",
        strings={"FileDescription": 'A "safe" tool', "CompanyName": "Acme\\Labs"},
        translations=[0x0409],
    )
    binary_round_trip = VersionInfo.from_bytes(rc_source.to_bytes())
    assert binary_round_trip.file_version == rc_source.file_version
    assert binary_round_trip.product_version == rc_source.product_version
    assert binary_round_trip.strings == {"CompanyName": "Acme\\Labs", "FileDescription": 'A "safe" tool'}
    assert binary_round_trip.translations == [0x0409]
    padded = VersionInfo.from_bytes(rc_source.to_bytes() + b"\x00\x00\x00\x00")
    assert any("trailing VERSIONINFO bytes" in warning for warning in padded.warnings)
    try:
        VersionInfo.from_bytes(b"bad")
        VersionInfo.from_bytes(rc_source.to_bytes() + (b"x" * 65))
    except ValueError:
        pass
    else:
        raise AssertionError("malformed VERSION resource was accepted")

    rc_round_trip = VersionInfo.from_rc(rc_source.to_rc())
    assert rc_round_trip.file_version == rc_source.file_version
    assert rc_round_trip.product_version == rc_source.product_version
    assert rc_round_trip.strings == rc_source.strings
    assert rc_round_trip.translations == rc_source.translations
    try:
        invalid.to_rc()
    except ValueError:
        pass
    else:
        raise AssertionError("invalid VersionInfo was serialized")
    print("version-info-tests: passed")


if __name__ == "__main__":
    main()

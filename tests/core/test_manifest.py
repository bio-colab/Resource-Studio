from __future__ import annotations

from core.manifest import ManifestDocument


VALID = """<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\"><assemblyIdentity name=\"Example\" version=\"1.0.0.0\"/><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo></assembly>"""


def main() -> None:
    document = ManifestDocument.parse(VALID)
    assert document.validate()["valid"] is True
    document.set_execution_level("highestAvailable", ui_access=True)
    report = document.validate()
    assert report["valid"] is True
    assert report["warnings"]
    assert "highestAvailable" in document.to_xml()

    try:
        ManifestDocument.parse("<not-a-manifest>")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed manifest was accepted")

    invalid = ManifestDocument.parse("<assembly />")
    assert invalid.validate()["valid"] is False
    print("manifest-tests: passed")


if __name__ == "__main__":
    main()

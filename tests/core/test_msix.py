from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

from core.msix import MSIXError, inspect_package


MANIFEST = """<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\"><Identity Name=\"Example\" Publisher=\"CN=Example\" Version=\"1.0.0.0\"/><Applications><Application Id=\"App\" Executable=\"app.exe\"/></Applications></Package>"""
BLOCKMAP = """<BlockMap HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\" xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\"><File Name=\"AppxManifest.xml\" Size=\"1\"><Block Hash=\"AA==\"/></File></BlockMap>"""


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-msix-") as directory:
        package = Path(directory) / "sample.msix"
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("AppxBlockMap.xml", BLOCKMAP)
            archive.writestr("resources.pri", b"PRI-test")
            archive.writestr("Assets/logo.png", b"PNG-test")
        report = inspect_package(package)
        assert report["valid"] is True
        assert report["signed"] is False
        assert report["manifest"]["identity"]["Name"] == "Example"
        assert report["blockMap"]["hashMethod"].endswith("sha256")
        assert report["pri"][0]["name"] == "resources.pri"

        unsafe = Path(directory) / "unsafe.msix"
        with zipfile.ZipFile(unsafe, "w") as archive:
            archive.writestr("../escape.txt", b"no")
        try:
            inspect_package(unsafe)
        except MSIXError:
            pass
        else:
            raise AssertionError("unsafe package member was accepted")
    print("msix-tests: passed")


if __name__ == "__main__":
    main()

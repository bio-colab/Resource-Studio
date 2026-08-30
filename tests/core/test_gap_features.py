from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from core.compatibility import inspect_compatibility
from core.invariants import compare_surgical_change
from core.pe_writer import LiefPEWriter
from core.project import Project
from core.rc_format import RCDocument
from core.search import search_resources
from core.signature import inspect_signature


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    original_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    compatibility = inspect_compatibility(FIXTURE)
    assert compatibility.resource_count >= 1
    signature = inspect_signature(FIXTURE)
    assert signature.present is False
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan = LiefPEWriter().plan_add_resource(FIXTURE, "RCDATA", 1900, 1033, b"plan")
        assert plan["willWrite"] is True and plan["outputPath"] is None
        output = root / "changed.dll"
        LiefPEWriter().add_resource(FIXTURE, output, "RCDATA", 1901, 1033, b"changed")
        assert compare_surgical_change(FIXTURE, output).valid
        project = Project.open_pe(FIXTURE, root / "project")
        with project.locked():
            assert project.lock_file.is_file()
        assert not project.lock_file.exists()
        hits = search_resources(project.entries.values(), "MANIFEST")
        assert hits and hits[0].field == "metadata"
    rc = RCDocument.from_text('''STRINGTABLE\nBEGIN\n IDS_HELLO "Hello"\nEND\n1 VERSIONINFO\n FILEVERSION 1,2,3,4\n PRODUCTVERSION 1,2,3,4\n BEGIN\n  BLOCK "StringFileInfo"\n  BEGIN\n   BLOCK "040904B0"\n   BEGIN\n    VALUE "FileDescription", "Demo"\n   END\n  END\n  BLOCK "VarFileInfo"\n  BEGIN\n   VALUE "Translation", 0x0409, 0x04B0\n  END\n END\nEND\n''')
    assert rc.string_tables[0].entries["IDS_HELLO"] == "Hello"
    assert RCDocument.from_text(rc.to_rc()).versions[0].file_version == "1.2.3.4"
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == original_hash
    print("gap-feature-tests: passed")


if __name__ == "__main__":
    main()

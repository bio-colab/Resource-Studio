from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.diff import diff_resources
from core.pe_writer import LiefPEWriter
from core.resource_reader import ResourceReader


FIXTURES = ROOT / "tests" / "fixtures"


def main() -> None:
    source_pe = FIXTURES / "sample.dll"

    with tempfile.TemporaryDirectory() as temporary:
        edited_pe = Path(temporary) / "edited.exe"

        # 1. Modify manifest in source_pe
        writer = LiefPEWriter()
        new_manifest = b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n<description>Modified Description</description>\n</assembly>"
        writer.replace_typed_resource(
            source_pe,
            edited_pe,
            "MANIFEST",
            1,
            1033,
            new_manifest,
        )

        before_entries = ResourceReader(source_pe).entries
        after_entries = ResourceReader(edited_pe).entries

        # Test default (hex diff)
        raw_diff = diff_resources(before_entries, after_entries, typed=False).to_dict()
        assert raw_diff["status"] == "modified"
        mod_nodes = [c for c in raw_diff["children"] if c["status"] == "modified"]
        assert len(mod_nodes) == 1
        assert mod_nodes[0]["key"] == "MANIFEST:1:1033"
        assert any(c["kind"] == "hex" for c in mod_nodes[0].get("children", []))

        # Test typed diff
        typed_diff = diff_resources(before_entries, after_entries, typed=True).to_dict()
        assert typed_diff["status"] == "modified"
        t_mod_nodes = [c for c in typed_diff["children"] if c["status"] == "modified"]
        assert len(t_mod_nodes) == 1
        assert t_mod_nodes[0]["key"] == "MANIFEST:1:1033"
        children = t_mod_nodes[0].get("children", [])
        assert len(children) > 0
        assert children[0]["kind"] == "unified-diff"
        assert "Modified Description" in children[0]["after"]["unified"]

    # 2. Test VersionInfo diff
    from core.project import ResourceEntry
    from core.version_info import VersionInfo

    heavy_pe = FIXTURES / "mingw_x64_resource_heavy.exe"
    reader = ResourceReader(heavy_pe)
    v_entry = [e for e in reader.entries if e.resource_type == "VERSION"][0]
    v_base = VersionInfo.from_bytes(v_entry.data)
    entry_before = ResourceEntry("VERSION", "1", 1033, v_base.to_bytes())
    v_modified = VersionInfo.from_bytes(v_entry.data)
    v_modified.set_string("CompanyName", "Adopted Innovations Corp")
    entry_after = ResourceEntry("VERSION", "1", 1033, v_modified.to_bytes())

    v_diff = diff_resources([entry_before], [entry_after], typed=True).to_dict()
    assert v_diff["status"] == "modified"
    v_mod = [c for c in v_diff["children"] if c["key"] == "VERSION:1:1033"][0]
    v_child_keys = [c["key"] for c in v_mod["children"]]
    assert "string:CompanyName" in v_child_keys
    mod_item = [c for c in v_mod["children"] if c["key"] == "string:CompanyName"][0]
    assert mod_item["before"]["value"] == "Resource Studio Corpus"
    assert mod_item["after"]["value"] == "Adopted Innovations Corp"

    # Test identical files
    entries = ResourceReader(source_pe).entries
    same_diff = diff_resources(entries, entries, typed=True).to_dict()
    assert same_diff["status"] == "unchanged"

    print("typed-diff-tests: passed")


if __name__ == "__main__":
    main()

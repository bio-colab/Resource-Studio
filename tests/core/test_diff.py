from __future__ import annotations

from core.diff import diff_resources, diff_texts
from core.project import ResourceEntry


def main() -> None:
    before = [
        ResourceEntry("STRING", "IDS_OLD", 1033, b"old"),
        ResourceEntry("RCDATA", "1", 1033, b"abc"),
        ResourceEntry("RCDATA", "2", 1033, b"same"),
    ]
    after = [
        ResourceEntry("STRING", "IDS_NEW", 1033, b"new"),
        ResourceEntry("RCDATA", "1", 1033, b"axc"),
        ResourceEntry("RCDATA", "2", 1033, b"same"),
    ]
    tree = diff_resources(before, after).to_dict()
    statuses = {node["key"]: node["status"] for node in tree["children"]}
    assert statuses["STRING:IDS_OLD:1033"] == "removed"
    assert statuses["STRING:IDS_NEW:1033"] == "added"
    assert statuses["RCDATA:1:1033"] == "modified"
    assert statuses["RCDATA:2:1033"] == "unchanged"
    modified = next(node for node in tree["children"] if node["key"] == "RCDATA:1:1033")
    assert modified["children"][0]["kind"] == "hex"

    texts = diff_texts({"hello": "Hello", "same": "same"}, {"hello": "مرحبا", "new": "New", "same": "same"}).to_dict()
    text_statuses = {node["key"]: node["status"] for node in texts["children"]}
    assert text_statuses == {"hello": "modified", "new": "added", "same": "unchanged"}
    print("diff-tests: passed")


if __name__ == "__main__":
    main()

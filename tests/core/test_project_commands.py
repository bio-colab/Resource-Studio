from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core import (
    AddResourceCommand,
    ChangeLanguageCommand,
    CommandHistory,
    DeleteResourceCommand,
    Project,
    ReplaceResourceCommand,
    ResourceEntry,
)


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        original = root / "original.exe"
        original.write_bytes(b"ORIGINAL-BINARY")
        original_hash = hashlib.sha256(original.read_bytes()).hexdigest()

        entry = ResourceEntry("STRING", "100", 1033, b"Hello")
        project = Project(
            root / "project",
            original_path=str(original),
            original_sha256=original_hash,
            entries=[entry],
        )
        history = CommandHistory()

        replacement = ResourceEntry("STRING", "100", 1033, "مرحبا".encode("utf-8"))
        history.execute(ReplaceResourceCommand(project, entry, replacement))
        assert project.get("STRING", "100", 1033).data == "مرحبا".encode("utf-8")
        history.undo()
        assert project.get("STRING", "100", 1033).data == b"Hello"
        history.redo()
        assert project.get("STRING", "100", 1033).data == "مرحبا".encode("utf-8")

        added = ResourceEntry("RCDATA", "1", None, b"payload")
        history.execute(AddResourceCommand(project, added))
        assert project.get("RCDATA", "1", None) is not None
        history.undo()
        assert project.get("RCDATA", "1", None) is None
        history.redo()
        assert project.get("RCDATA", "1", None) is not None

        history.execute(ChangeLanguageCommand(project, replacement, 1025))
        assert project.get("STRING", "100", 1033) is None
        assert project.get("STRING", "100", 1025).data == "مرحبا".encode("utf-8")
        history.undo()
        assert project.get("STRING", "100", 1033).data == "مرحبا".encode("utf-8")

        deleted = project.get("RCDATA", "1", None)
        assert deleted is not None
        history.execute(DeleteResourceCommand(project, deleted))
        assert project.get("RCDATA", "1", None) is None
        history.undo()
        assert project.get("RCDATA", "1", None) is not None

        project.save()
        loaded = Project.load(project.project_dir)
        assert loaded.original_sha256 == original_hash
        assert loaded.get("STRING", "100", 1033).data == "مرحبا".encode("utf-8")
        assert loaded.get("RCDATA", "1", None).data == b"payload"
        snapshot = loaded.snapshot("after-undo-redo")
        assert snapshot.is_file()
        assert original.read_bytes() == b"ORIGINAL-BINARY"
        assert hashlib.sha256(original.read_bytes()).hexdigest() == original_hash

    print("project-command-tests: passed")


if __name__ == "__main__":
    main()

from __future__ import annotations

import tempfile
from pathlib import Path

from core.commands import CommandHistory
from core.project import Project, ResourceEntry


class MutatingExecuteFailure:
    description = "mutating execute failure"

    def __init__(self, project: Project, entry: ResourceEntry) -> None:
        self.project = project
        self.entry = entry

    def execute(self) -> None:
        self.project.put(self.entry)
        raise RuntimeError("execute failed")

    def undo(self) -> None:
        self.project.remove(*self.entry.key)


class MutatingUndoFailure:
    description = "mutating undo failure"

    def __init__(self, project: Project, entry: ResourceEntry) -> None:
        self.project = project
        self.entry = entry

    def execute(self) -> None:
        self.project.put(self.entry)

    def undo(self) -> None:
        self.project.remove(*self.entry.key)
        raise RuntimeError("undo failed")


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        project = Project(Path(temporary))
        entry = ResourceEntry("STRING", "IDS_TEST", 1033, b"value")
        history = CommandHistory()

        try:
            history.execute(MutatingExecuteFailure(project, entry))
        except RuntimeError:
            pass
        else:
            raise AssertionError("execute failure was not propagated")
        assert project.get(*entry.key) is None
        assert not history.can_undo
        assert any(event["operation"] == "command.execute.failed" for event in project.audit.read())
        assert list(project.snapshots_dir.glob("*.json")), "execute did not create a snapshot"

        stable = ResourceEntry("STRING", "IDS_STABLE", 1033, b"stable")
        history.execute(MutatingUndoFailure(project, stable))
        assert project.get(*stable.key) == stable
        try:
            history.undo()
        except RuntimeError:
            pass
        else:
            raise AssertionError("undo failure was not propagated")
        assert project.get(*stable.key) == stable
        assert history.can_undo
        assert not history.can_redo
        assert any(event["operation"] == "command.undo.failed" for event in project.audit.read())
    print("command-atomic-tests: passed")


if __name__ == "__main__":
    main()

from __future__ import annotations

import tempfile
from pathlib import Path

from core.commands import AddResourceCommand, ChangeIdCommand, CommandHistory, DeleteResourceCommand
from core.project import Project, ResourceEntry


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        project = Project(Path(temporary) / "project", entries=[ResourceEntry("STRING", "OLD", 1033, b"old")])
        history = CommandHistory(snapshot_project=project)
        original = project.get("STRING", "OLD", 1033)
        assert original is not None
        rename = ChangeIdCommand(project, original, "NEW")
        history.execute(rename)
        assert project.get("STRING", "OLD", 1033) is None
        assert project.get("STRING", "NEW", 1033) is not None
        history.undo()
        assert project.get("STRING", "OLD", 1033) is not None

        added = ResourceEntry("STRING", "ADDED", 1033, b"added")
        history.execute_group([AddResourceCommand(project, added), DeleteResourceCommand(project, original)], description="batch")
        assert project.get("STRING", "ADDED", 1033) is not None
        assert project.get("STRING", "OLD", 1033) is None
        history.undo()
        assert project.get("STRING", "ADDED", 1033) is None
        assert project.get("STRING", "OLD", 1033) is not None
        history.redo()
        assert project.get("STRING", "ADDED", 1033) is not None
        assert project.get("STRING", "OLD", 1033) is None
    print("command-grouping-tests: passed")


if __name__ == "__main__":
    main()

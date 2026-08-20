from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .project import Project, ResourceEntry


class Command(Protocol):
    description: str

    def execute(self) -> None: ...

    def undo(self) -> None: ...


@dataclass
class ReplaceResourceCommand:
    project: Project
    before: ResourceEntry
    after: ResourceEntry
    description: str = "Replace resource"

    def execute(self) -> None:
        self.project.put(self.after)

    def undo(self) -> None:
        self.project.put(self.before)


@dataclass
class AddResourceCommand:
    project: Project
    entry: ResourceEntry
    description: str = "Add resource"

    def execute(self) -> None:
        if self.project.get(*self.entry.key) is not None:
            raise ValueError(f"resource already exists: {self.entry.key}")
        self.project.put(self.entry)

    def undo(self) -> None:
        self.project.remove(*self.entry.key)


@dataclass
class DeleteResourceCommand:
    project: Project
    entry: ResourceEntry
    description: str = "Delete resource"

    def execute(self) -> None:
        self.project.remove(*self.entry.key)

    def undo(self) -> None:
        self.project.put(self.entry)


@dataclass
class ChangeIdCommand:
    project: Project
    before: ResourceEntry
    new_name: str
    description: str = "Change resource id"
    _after: ResourceEntry | None = field(default=None, init=False, repr=False)

    def execute(self) -> None:
        if self.project.get(*self.before.key) is None:
            raise ValueError(f"resource not found: {self.before.key}")
        target_key = (self.before.resource_type, self.new_name, self.before.language)
        if self.project.get(*target_key) is not None:
            raise ValueError(f"resource already exists: {target_key}")
        self._after = ResourceEntry(
            self.before.resource_type,
            self.new_name,
            self.before.language,
            self.before.data,
            dict(self.before.metadata or {}),
        )
        self.project.remove(*self.before.key)
        self.project.put(self._after)

    def undo(self) -> None:
        if self._after is not None and self.project.get(*self._after.key) is not None:
            self.project.remove(*self._after.key)
        self.project.put(self.before)


RenameResourceCommand = ChangeIdCommand


@dataclass
class ChangeLanguageCommand:
    project: Project
    before: ResourceEntry
    target_language: int | None
    description: str = "Change resource language"
    _after: ResourceEntry | None = field(default=None, init=False, repr=False)

    def execute(self) -> None:
        if self.project.get(*self.before.key) is None:
            raise ValueError(f"resource not found: {self.before.key}")
        if self.project.get(self.before.resource_type, self.before.name, self.target_language) is not None:
            raise ValueError("target language resource already exists")
        self._after = ResourceEntry(
            self.before.resource_type,
            self.before.name,
            self.target_language,
            self.before.data,
            dict(self.before.metadata or {}),
        )
        self.project.remove(*self.before.key)
        self.project.put(self._after)

    def undo(self) -> None:
        if self._after is not None and self.project.get(*self._after.key) is not None:
            self.project.remove(*self._after.key)
        self.project.put(self.before)


@dataclass
class CommandGroup:
    commands: tuple[Command, ...]
    description: str = "Grouped resource edit"

    @property
    def project(self) -> Project | None:
        return next((getattr(command, "project", None) for command in self.commands if getattr(command, "project", None) is not None), None)

    def execute(self) -> None:
        executed: list[Command] = []
        try:
            for command in self.commands:
                command.execute()
                executed.append(command)
        except Exception:
            for command in reversed(executed):
                try:
                    command.undo()
                except Exception:
                    pass
            raise

    def undo(self) -> None:
        for command in reversed(self.commands):
            command.undo()


@dataclass
class HistoryItem:
    command: Command
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CommandHistory:
    """Undo/redo history with project snapshots and durable audit events.

    A failed command is treated as a transaction: the in-memory project state and
    history stack are restored before the exception is re-raised.
    """

    def __init__(self, *, snapshot_project: Project | None = None) -> None:
        self._done: list[HistoryItem] = []
        self._undone: list[HistoryItem] = []
        self.snapshot_project = snapshot_project

    @property
    def can_undo(self) -> bool:
        return bool(self._done)

    @property
    def can_redo(self) -> bool:
        return bool(self._undone)

    @property
    def items(self) -> tuple[HistoryItem, ...]:
        return tuple(self._done)

    def execute(self, command: Command) -> None:
        project = self._project_for(command)
        state = _capture_state(project)
        snapshot = self._snapshot(project, "before-execute")
        try:
            command.execute()
        except Exception as exc:
            _restore_state(project, state)
            self._record(project, "command.execute.failed", command, snapshot, error=str(exc))
            raise
        self._done.append(HistoryItem(command))
        self._undone.clear()
        self._record(project, "command.execute", command, snapshot)

    def execute_group(self, commands: list[Command] | tuple[Command, ...], *, description: str = "Grouped resource edit") -> None:
        if not commands:
            raise ValueError("command group cannot be empty")
        self.execute(CommandGroup(tuple(commands), description))

    def undo(self) -> None:
        if not self._done:
            raise IndexError("nothing to undo")
        item = self._done[-1]
        project = self._project_for(item.command)
        state = _capture_state(project)
        snapshot = self._snapshot(project, "before-undo")
        try:
            item.command.undo()
        except Exception as exc:
            _restore_state(project, state)
            self._record(project, "command.undo.failed", item.command, snapshot, error=str(exc))
            raise
        self._done.pop()
        self._undone.append(item)
        self._record(project, "command.undo", item.command, snapshot)

    def redo(self) -> None:
        if not self._undone:
            raise IndexError("nothing to redo")
        item = self._undone[-1]
        project = self._project_for(item.command)
        state = _capture_state(project)
        snapshot = self._snapshot(project, "before-redo")
        try:
            item.command.execute()
        except Exception as exc:
            _restore_state(project, state)
            self._record(project, "command.redo.failed", item.command, snapshot, error=str(exc))
            raise
        self._undone.pop()
        self._done.append(item)
        self._record(project, "command.redo", item.command, snapshot)

    def _project_for(self, command: Command) -> Project | None:
        project = getattr(command, "project", None) or self.snapshot_project
        return project if isinstance(project, Project) else None

    @staticmethod
    def _snapshot(project: Project | None, action: str) -> str | None:
        if project is None:
            return None
        was_dirty = project.dirty
        label = f"command-{action}-{uuid.uuid4().hex[:10]}"
        try:
            return str(project.snapshot(label))
        finally:
            project.dirty = was_dirty

    @staticmethod
    def _record(project: Project | None, operation: str, command: Command, snapshot: str | None, **extra: Any) -> None:
        if project is None:
            return
        details = {"description": getattr(command, "description", type(command).__name__), "snapshot": snapshot}
        details.update(extra)
        try:
            project.audit.append(operation, **details)
        except OSError:
            # A broken audit destination must not turn a completed edit into a half-history.
            pass


def _capture_state(project: Project | None) -> tuple[dict[tuple[str, str, int | None], ResourceEntry], bool] | None:
    if project is None:
        return None
    return copy.deepcopy(project.entries), project.dirty


def _restore_state(project: Project | None, state: tuple[dict[tuple[str, str, int | None], ResourceEntry], bool] | None) -> None:
    if project is None or state is None:
        return
    entries, dirty = state
    project.entries = entries
    project.dirty = dirty

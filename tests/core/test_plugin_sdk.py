from __future__ import annotations

import tempfile
from pathlib import Path

from core.commands import AddResourceCommand, CommandHistory
from core.plugins import PluginContext, PluginManifest, PluginRegistry
from core.project import Project, ResourceEntry


def make_manifest(permissions: list[str], plugin_id: str = "com.example.sdk") -> PluginManifest:
    return PluginManifest.from_dict(
        {
            "id": plugin_id,
            "name": "SDK",
            "version": "1.0.0",
            "api": "resource-editor/v1",
            "entry": "plugin.py",
            "permissions": permissions,
        }
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        project = Project(Path(temporary) / "project", entries=[ResourceEntry("STRING", "IDS_ONE", 1033, b"one")])
        registry = PluginRegistry(audit_path=Path(temporary) / "audit.jsonl")
        manifest = make_manifest(["project.read", "project.modify"])
        registry.register(manifest)
        context = PluginContext(registry, manifest.plugin_id, project=project)
        assert context.read_resource("STRING", "IDS_ONE", 1033) == b"one"
        context.put_resource(ResourceEntry("STRING", "IDS_TWO", 1033, b"two"))
        assert context.get_resource("STRING", "IDS_TWO", 1033) is not None
        history = CommandHistory(snapshot_project=project)
        context_with_history = PluginContext(registry, manifest.plugin_id, project=project, history=history)
        command_entry = ResourceEntry("STRING", "IDS_COMMAND", 1033, b"command")
        context_with_history.execute_command(AddResourceCommand(project, command_entry))
        assert project.get(*command_entry.key) == command_entry
        context_with_history.undo_command()
        assert project.get(*command_entry.key) is None
        context.log("test", value="ok")
        operations = [event["operation"] for event in registry._audit.read()]
        assert operations.count("plugin.event") >= 4

        read_only = make_manifest(["project.read"], "com.example.readonly")
        registry.register(read_only)
        read_context = PluginContext(registry, read_only.plugin_id, project=project)
        try:
            read_context.put_resource(ResourceEntry("STRING", "IDS_THREE", 1033, b"three"))
        except PermissionError:
            pass
        else:
            raise AssertionError("read-only plugin modified a project")
    print("plugin-sdk-tests: passed")


if __name__ == "__main__":
    main()

from __future__ import annotations

import tempfile
from pathlib import Path

from core.plugins import PluginManifest, PluginRegistry, ResourceTypeDefinition


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        registry = PluginRegistry(audit_path=Path(temporary) / "audit.jsonl")
        manifest = PluginManifest.from_dict(
            {
                "id": "com.example.game",
                "name": "Game data",
                "version": "1.0.0",
                "api": "resource-editor/v1",
                "entry": "plugin.py",
                "permissions": ["project.read"],
                "kind": "parser",
            }
        )
        registry.register(manifest)
        definition = ResourceTypeDefinition(
            "GAME_DATA",
            manifest.plugin_id,
            parser="game.parse",
            viewer="game.view",
            serializer="game.serialize",
        )
        registry.register_resource_type(definition)
        assert registry.resource_type("GAME_DATA") == definition
        assert [item.type_name for item in registry.resource_types()] == ["GAME_DATA"]
        registry.disable(manifest.plugin_id, "test quarantine")
        try:
            registry.resource_type("GAME_DATA")
        except RuntimeError:
            pass
        else:
            raise AssertionError("disabled plugin exposed a custom resource type")
    print("custom-resource-type-tests: passed")


if __name__ == "__main__":
    main()

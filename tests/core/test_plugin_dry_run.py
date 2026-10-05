from __future__ import annotations

import tempfile
from pathlib import Path

from core.plugin_host import PluginHost
from core.plugins import PluginManifest, PluginRegistry


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        entry = directory / "plugin.py"
        entry.write_text("raise RuntimeError('must not execute in dry-run')\n", encoding="utf-8")
        registry = PluginRegistry()
        manifest = PluginManifest.from_dict(
            {
                "id": "com.example.script",
                "name": "Script",
                "version": "1.0.0",
                "api": "resource-editor/v1",
                "entry": "plugin.py",
                "permissions": ["project.read"],
                "kind": "automation",
            }
        )
        registry.register(manifest)
        plan = PluginHost().dry_run_registered(registry, manifest.plugin_id, directory, {"operation": "list"})
        assert plan["wouldExecute"] is False
        assert plan["request"]["operation"] == "list"
        assert registry.is_enabled(manifest.plugin_id)
    print("plugin-dry-run-tests: passed")


if __name__ == "__main__":
    main()

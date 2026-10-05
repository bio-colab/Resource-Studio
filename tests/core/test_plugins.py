from __future__ import annotations

import json
import tempfile
from pathlib import Path

from core.plugins import PluginContext, PluginManifest, PluginRegistry


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "manifest.json"
        path.write_text(
            json.dumps(
                {
                    "id": "com.example.xliff-importer",
                    "name": "XLIFF Importer",
                    "version": "1.0.0",
                    "api": "resource-editor/v1",
                    "entry": "plugin.wasm",
                    "kind": "importer",
                    "permissions": ["project.read", "files.read"],
                }
            ),
            encoding="utf-8",
        )
        registry = PluginRegistry()
        manifest = registry.register_file(path)
        assert manifest.plugin_id == "com.example.xliff-importer"
        assert registry.can(manifest.plugin_id, "project.read")
        assert not registry.can(manifest.plugin_id, "project.modify")
        context = PluginContext(registry, manifest.plugin_id)
        context.require("project.read")
        try:
            context.require("project.modify")
        except PermissionError:
            pass
        else:
            raise AssertionError("undeclared permission was accepted")

        bad = dict(json.loads(path.read_text(encoding="utf-8")))
        bad["permissions"] = ["root.shell"]
        try:
            PluginManifest.from_dict(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("unknown permission was accepted")

    print("plugin-tests: passed")


if __name__ == "__main__":
    main()

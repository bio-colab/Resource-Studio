from __future__ import annotations

import tempfile
from pathlib import Path

from core.plugin_host import PluginHost, PluginHostError
from core.plugins import PluginContext, PluginManifest, PluginRegistry


CRASHER = "raise SystemExit(1)\n"


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        (directory / "plugin.py").write_text(CRASHER, encoding="utf-8")
        audit_path = directory / "audit.jsonl"
        registry = PluginRegistry(audit_path=audit_path)
        manifest = PluginManifest.from_dict(
            {
                "id": "com.example.crasher",
                "name": "Crasher",
                "version": "1.0.0",
                "api": "resource-editor/v1",
                "entry": "plugin.py",
                "permissions": ["project.read"],
            }
        )
        registry.register(manifest)
        context = PluginContext(registry, manifest.plugin_id)
        context.require("project.read")
        try:
            PluginHost().run_registered(registry, manifest.plugin_id, directory, {})
        except PluginHostError:
            pass
        else:
            raise AssertionError("crashing plugin did not fail")
        assert not registry.is_enabled(manifest.plugin_id)
        assert "exited with" in (registry.disabled_reason(manifest.plugin_id) or "")
        try:
            context.require("project.read")
        except RuntimeError:
            pass
        else:
            raise AssertionError("disabled plugin still passed permission gate")
        assert any(event["operation"] == "plugin.disabled" for event in registry._audit.read())
        registry.enable(manifest.plugin_id)
        context.require("project.read")
        assert registry.is_enabled(manifest.plugin_id)
    print("plugin-quarantine-tests: passed")


if __name__ == "__main__":
    main()

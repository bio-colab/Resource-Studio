from __future__ import annotations

import json
import tempfile
from pathlib import Path

from core.plugin_host import PluginHost, PluginHostError, PluginLimits
from core.plugins import PluginManifest


PLUGIN = """import json\nimport sys\nrequest = json.loads(sys.stdin.readline())\nprint(json.dumps({\"ok\": True, \"echo\": request.get(\"value\"), \"plugin\": __import__(\"os\").environ.get(\"RESOURCE_STUDIO_PLUGIN_ID\")}))\n"""


def main() -> None:
    manifest = PluginManifest.from_dict(
        {
            "id": "com.example.echo",
            "name": "Echo",
            "version": "1.0.0",
            "api": "resource-editor/v1",
            "entry": "plugin.py",
            "permissions": ["project.read"],
        }
    )
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        (directory / "plugin.py").write_text(PLUGIN, encoding="utf-8")
        result = PluginHost().run(manifest, directory, {"value": "ok"})
        assert result.response == {"ok": True, "echo": "ok", "plugin": "com.example.echo"}
        try:
            PluginHost().run(manifest, directory, {"value": "x" * 100}, limits=PluginLimits(max_request_bytes=32))
        except PluginHostError:
            pass
        else:
            raise AssertionError("oversized plugin request was accepted")

        bad = PluginManifest.from_dict(
            {
                "id": "com.example.bad",
                "name": "Bad",
                "version": "1.0.0",
                "api": "resource-editor/v1",
                "entry": "../outside.py",
                "permissions": ["project.read"],
            }
        )
        try:
            PluginHost().run(bad, directory, {})
        except PluginHostError:
            pass
        else:
            raise AssertionError("plugin entry outside directory was accepted")
    print("plugin-host-tests: passed")


if __name__ == "__main__":
    main()

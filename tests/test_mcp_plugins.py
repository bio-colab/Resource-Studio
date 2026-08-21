from __future__ import annotations

import anyio
import json
import shutil
import sys
import tempfile
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SERVER = PROJECT_ROOT / "mcp" / "server.py"
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "sample.dll"


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-mcp-plugins-") as directory:
        root = Path(directory)
        shutil.copy2(FIXTURE, root / "sample.dll")
        valid = root / ".resource-studio" / "plugins" / "sample.viewer" / "plugin.json"
        valid.parent.mkdir(parents=True)
        valid.write_text(
            json.dumps(
                {
                    "id": "sample.viewer",
                    "name": "Sample Viewer",
                    "version": "1.0.0",
                    "api": "resource-editor/v1",
                    "entry": "plugin_main",
                    "permissions": ["project.read"],
                    "kind": "viewer",
                }
            ),
            encoding="utf-8",
        )
        invalid = root / ".resource-studio" / "plugins" / "invalid" / "plugin.json"
        invalid.parent.mkdir(parents=True)
        invalid.write_text(json.dumps({"id": "BAD ID", "version": "nope"}), encoding="utf-8")
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(SERVER)],
            cwd=str(PROJECT_ROOT),
            env={"RESOURCE_STUDIO_ROOT": str(root)},
        )
        async with stdio_client(params) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                listed = await session.call_tool("resource_studio.list_plugins", {})
                assert not listed.is_error
                plugins = listed.structured_content["plugins"]
                assert any(item.get("pluginId") == "sample.viewer" and item["status"] == "discovered" and not item["executesCode"] for item in plugins)
                assert any(item.get("manifestPath", "").endswith("invalid/plugin.json") and item["status"] == "rejected" for item in plugins)
                resource = await session.read_resource("resource://plugins")
                payload = json.loads(resource.contents[0].text)
                assert any(item.get("pluginId") == "sample.viewer" for item in payload["plugins"])


if __name__ == "__main__":
    anyio.run(main)
    print("mcp-plugin-tests: passed")

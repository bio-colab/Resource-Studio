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

ECHO_PLUGIN = """import json\nimport os\nrequest = json.loads(input())\nprint(json.dumps({\"ok\": True, \"value\": request.get(\"value\"), \"permissions\": os.environ.get(\"RESOURCE_STUDIO_PLUGIN_PERMISSIONS\")}))\n"""
CRASH_PLUGIN = "raise RuntimeError('intentional plugin failure')\n"


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-mcp-plugin-runtime-") as directory:
        root = Path(directory)
        shutil.copy2(FIXTURE, root / "sample.dll")
        echo_dir = root / ".resource-studio" / "plugins" / "echo.plugin"
        echo_dir.mkdir(parents=True)
        (echo_dir / "plugin.json").write_text(
            json.dumps(
                {
                    "id": "echo.plugin",
                    "name": "Echo Plugin",
                    "version": "1.0.0",
                    "api": "resource-editor/v1",
                    "entry": "plugin.py",
                    "permissions": ["project.read"],
                    "kind": "viewer",
                }
            ),
            encoding="utf-8",
        )
        (echo_dir / "plugin.py").write_text(ECHO_PLUGIN, encoding="utf-8")
        crash_dir = root / ".resource-studio" / "plugins" / "crash.plugin"
        crash_dir.mkdir(parents=True)
        (crash_dir / "plugin.json").write_text(
            json.dumps(
                {
                    "id": "crash.plugin",
                    "name": "Crash Plugin",
                    "version": "1.0.0",
                    "api": "resource-editor/v1",
                    "entry": "plugin.py",
                    "permissions": ["project.read"],
                }
            ),
            encoding="utf-8",
        )
        (crash_dir / "plugin.py").write_text(CRASH_PLUGIN, encoding="utf-8")
        admin_token = "local-admin-token-for-test-32-characters"
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(SERVER)],
            cwd=str(PROJECT_ROOT),
            env={"RESOURCE_STUDIO_ROOT": str(root), "RESOURCE_STUDIO_MCP_ADMIN_TOKEN": admin_token, "RESOURCE_STUDIO_MCP_ALLOW_PLUGIN_EXECUTION": "true"},
        )
        async with stdio_client(params) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                inspected = await session.call_tool("resource_studio.inspect_plugin", {"plugin_id": "echo.plugin"})
                assert not inspected.is_error
                assert inspected.structured_content["runtimePolicy"]["outOfProcess"] is True

                plan = await session.call_tool(
                    "resource_studio.plan_plugin_execution",
                    {"plugin_id": "echo.plugin", "request": {"value": "ok"}, "granted_permissions": ["project.read"]},
                )
                assert not plan.is_error
                plan_data = plan.structured_content
                applied = await session.call_tool(
                    "resource_studio.apply_plugin_execution",
                    {
                        "plan_id": plan_data["planId"],
                        "confirmation_token": plan_data["confirmationToken"],
                        "confirmed": True,
                        "admin_confirmation_token": admin_token,
                    },
                )
                assert not applied.is_error
                assert applied.structured_content["status"] == "completed"
                assert applied.structured_content["response"]["value"] == "ok"
                assert applied.structured_content["response"]["permissions"] == "[\"project.read\"]"

                rejected = await session.call_tool(
                    "resource_studio.plan_plugin_execution",
                    {"plugin_id": "echo.plugin", "request": {}, "granted_permissions": ["network"]},
                )
                assert rejected.is_error

                crash_plan = await session.call_tool(
                    "resource_studio.plan_plugin_execution",
                    {"plugin_id": "crash.plugin", "request": {}, "granted_permissions": ["project.read"]},
                )
                crash_data = crash_plan.structured_content
                failed = await session.call_tool(
                    "resource_studio.apply_plugin_execution",
                    {
                        "plan_id": crash_data["planId"],
                        "confirmation_token": crash_data["confirmationToken"],
                        "confirmed": True,
                        "admin_confirmation_token": admin_token,
                    },
                )
                assert failed.is_error
                listed = await session.call_tool("resource_studio.list_plugins", {})
                crash_record = next(item for item in listed.structured_content["plugins"] if item.get("pluginId") == "crash.plugin")
                assert crash_record["enabled"] is False
                assert crash_record["disabledReason"]
                reenabled = await session.call_tool("resource_studio.enable_plugin", {"plugin_id": "crash.plugin", "admin_confirmation_token": admin_token})
                assert not reenabled.is_error


if __name__ == "__main__":
    anyio.run(main)
    print("mcp-plugin-runtime-tests: passed")

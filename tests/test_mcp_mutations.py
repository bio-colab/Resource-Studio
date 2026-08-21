from __future__ import annotations

import anyio
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
    with tempfile.TemporaryDirectory(prefix="resource-studio-mcp-mutations-") as directory:
        root = Path(directory)
        shutil.copy2(FIXTURE, root / "sample.dll")
        (root / "payload.bin").write_bytes(b"mcp-add-payload")
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(SERVER)],
            cwd=str(PROJECT_ROOT),
            env={"RESOURCE_STUDIO_ROOT": str(root)},
        )
        async with stdio_client(params) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                registered = await session.call_tool("resource_studio.register_file", {"path": "sample.dll"})
                file_id = registered.structured_content["fileId"]

                add_workspace = await session.call_tool("resource_studio.create_workspace", {"file_id": file_id})
                add_ws = add_workspace.structured_content
                add_plan = await session.call_tool(
                    "resource_studio.plan_resource_change",
                    {
                        "workspace_id": add_ws["workspaceId"],
                        "operation": "add",
                        "resource_type": "RCDATA",
                        "resource_name": "500",
                        "language": 1033,
                        "payload_path": "payload.bin",
                    },
                )
                add_result = await session.call_tool(
                    "resource_studio.apply_plan",
                    {
                        "plan_id": add_plan.structured_content["planId"],
                        "confirmation_token": add_plan.structured_content["confirmationToken"],
                        "confirmed": True,
                    },
                )
                assert not add_result.is_error
                assert add_result.structured_content["status"] == "verified"
                assert add_result.structured_content["changes"][0]["action"] == "add"
                Path(add_result.structured_content["outputPath"]).unlink(missing_ok=True)

                delete_workspace = await session.call_tool("resource_studio.create_workspace", {"file_id": file_id})
                delete_ws = delete_workspace.structured_content
                delete_plan = await session.call_tool(
                    "resource_studio.plan_resource_change",
                    {
                        "workspace_id": delete_ws["workspaceId"],
                        "operation": "delete",
                        "resource_type": "MANIFEST",
                        "resource_name": "1",
                    },
                )
                delete_result = await session.call_tool(
                    "resource_studio.apply_plan",
                    {
                        "plan_id": delete_plan.structured_content["planId"],
                        "confirmation_token": delete_plan.structured_content["confirmationToken"],
                        "confirmed": True,
                    },
                )
                assert not delete_result.is_error
                assert delete_result.structured_content["status"] == "verified"
                assert delete_result.structured_content["changes"][0]["action"] == "delete"
                Path(delete_result.structured_content["outputPath"]).unlink(missing_ok=True)

                language_workspace = await session.call_tool("resource_studio.create_workspace", {"file_id": file_id})
                language_ws = language_workspace.structured_content
                language_plan = await session.call_tool(
                    "resource_studio.plan_resource_change",
                    {
                        "workspace_id": language_ws["workspaceId"],
                        "operation": "change-language",
                        "resource_type": "MANIFEST",
                        "resource_name": "1",
                        "target_language": 1025,
                    },
                )
                language_result = await session.call_tool(
                    "resource_studio.apply_plan",
                    {
                        "plan_id": language_plan.structured_content["planId"],
                        "confirmation_token": language_plan.structured_content["confirmationToken"],
                        "confirmed": True,
                    },
                )
                assert not language_result.is_error
                assert language_result.structured_content["status"] == "verified"
                assert language_result.structured_content["changes"][0]["action"] == "change-language"
                assert language_result.structured_content["changes"][0]["targetLanguage"] == "1025"
                Path(language_result.structured_content["outputPath"]).unlink(missing_ok=True)

                for workspace in (add_ws, delete_ws, language_ws):
                    shutil.rmtree(Path(workspace["workspacePath"]).parent, ignore_errors=True)


if __name__ == "__main__":
    anyio.run(main)
    print("mcp-mutation-tests: passed")

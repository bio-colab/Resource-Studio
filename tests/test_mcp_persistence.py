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


async def register(root: Path) -> tuple[str, str]:
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
            assert not registered.is_error
            payload = registered.structured_content
            workspace = await session.call_tool("resource_studio.create_workspace", {"file_id": payload["fileId"]})
            assert not workspace.is_error
            return payload["fileId"], workspace.structured_content["workspaceId"]


async def inspect_after_restart(root: Path, file_id: str, workspace_id: str) -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        cwd=str(PROJECT_ROOT),
        env={"RESOURCE_STUDIO_ROOT": str(root)},
    )
    async with stdio_client(params) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            inspected = await session.call_tool("resource_studio.inspect_file", {"file_id": file_id})
            assert not inspected.is_error
            assert inspected.structured_content["file"]["fileId"] == file_id
            workspace = await session.read_resource(f"resource://workspace/{workspace_id}")
            workspace_payload = json.loads(workspace.contents[0].text)
            assert workspace_payload["workspace_id"] == workspace_id


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-mcp-state-") as directory:
        root = Path(directory)
        shutil.copy2(FIXTURE, root / "sample.dll")
        file_id, workspace_id = await register(root)
        state_path = root / ".resource-studio" / "mcp-state.json"
        assert state_path.is_file()
        await inspect_after_restart(root, file_id, workspace_id)


if __name__ == "__main__":
    anyio.run(main)
    print("mcp-persistence-tests: passed")

from __future__ import annotations

import anyio
import json
import shutil
import sys
import tempfile
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "mcp" / "server.py"
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-mcp-observability-") as directory:
        root = Path(directory)
        shutil.copy2(FIXTURE, root / FIXTURE.name)
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(SERVER)],
            cwd=str(ROOT),
            env={"RESOURCE_STUDIO_ROOT": str(root)},
        )
        async with stdio_client(params) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()

                tools = await session.list_tools()
                tool_names = {tool.name for tool in tools.tools}
                resources = await session.list_resources()
                resource_uris = {str(resource.uri) for resource in resources.resources}
                assert "resource://session/state" in resource_uris
                assert "resource://session/events" in resource_uris
                assert "resource://tools/metadata" in resource_uris

                metadata_document = await session.read_resource("resource://tools/metadata")
                metadata = json.loads(metadata_document.contents[0].text)
                assert metadata["schemaVersion"] == "resource_studio.tool_metadata.v1"
                assert set(metadata["tools"]) >= tool_names
                assert metadata["tools"]["resource_studio.apply_plan"]["readOnly"] is False
                assert metadata["tools"]["resource_studio.apply_plan"]["confirmation"] == "human confirmation required"

                registered = await session.call_tool(
                    "resource_studio.register_file", {"path": FIXTURE.name}
                )
                assert not registered.is_error
                file_id = registered.structured_content["fileId"]
                workspace = await session.call_tool(
                    "resource_studio.create_workspace", {"file_id": file_id}
                )
                assert not workspace.is_error

                state_document = await session.read_resource("resource://session/state")
                state = json.loads(state_document.contents[0].text)
                assert state["schemaVersion"] == "resource_studio.session_state.v1"
                assert state["readOnly"] is True
                assert state["counts"]["workspaces"] == 1
                assert state["lastEventSequence"] >= 2

                events_document = await session.read_resource("resource://session/events")
                events = json.loads(events_document.contents[0].text)
                assert events["schemaVersion"] == "resource_studio.events.v1"
                kinds = {event["kind"] for event in events["events"]}
                assert {"file.registered", "workspace.created"}.issubset(kinds)
                assert all(event["readOnly"] is True for event in events["events"])

    print("mcp-observability-tests: passed")


if __name__ == "__main__":
    anyio.run(main)

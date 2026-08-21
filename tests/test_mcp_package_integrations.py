from __future__ import annotations

import anyio
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SERVER = PROJECT_ROOT / "mcp" / "server.py"

MANIFEST = "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\"><Identity Name=\"Example\" Publisher=\"CN=Example\" Version=\"1.0.0.0\"/></Package>"


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-mcp-package-") as directory:
        root = Path(directory)
        package = root / "sample.msix"
        payload = root / "payload.txt"
        payload.write_text("new", encoding="utf-8")
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("resources.pri", b"PRI-test")
            archive.writestr("old.txt", b"old")
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(SERVER)],
            cwd=str(PROJECT_ROOT),
            env={"RESOURCE_STUDIO_ROOT": str(root)},
        )
        async with stdio_client(params) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                inspected = await session.call_tool("resource_studio.inspect_package", {"path": "sample.msix"})
                assert not inspected.is_error
                assert inspected.structured_content["valid"] is True
                assert inspected.structured_content["pri"][0]["name"] == "resources.pri"
                integrations = await session.call_tool("resource_studio.list_integrations", {})
                assert not integrations.is_error
                plan = await session.call_tool(
                    "resource_studio.plan_package_change",
                    {"path": "sample.msix", "action": "replace", "member_name": "old.txt", "payload_path": "payload.txt"},
                )
                assert not plan.is_error
                assert plan.structured_content["engine"] == "MakeAppx.exe"
                assert plan.structured_content["payloadSha256"]
                result = await session.call_tool(
                    "resource_studio.apply_package_change",
                    {
                        "plan_id": plan.structured_content["planId"],
                        "confirmation_token": plan.structured_content["confirmationToken"],
                        "confirmed": True,
                    },
                )
                if sys.platform != "win32":
                    assert result.is_error
                assert package.is_file()
                assert package.stat().st_size > 0


if __name__ == "__main__":
    anyio.run(main)
    print("mcp-package-integration-tests: passed")

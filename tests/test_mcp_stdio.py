from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from urllib.parse import quote

import anyio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SERVER = PROJECT_ROOT / "mcp" / "server.py"
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "sample.dll"
NON_PE = PROJECT_ROOT / "tests" / "fixtures" / "not-pe.txt"
PAYLOAD = PROJECT_ROOT / "tests" / "fixtures" / "payload_same_size.bin"
EXPORT = PROJECT_ROOT / "tests" / "fixtures" / "mcp_export_output.dll"


async def main() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        cwd=str(PROJECT_ROOT),
        env={"RESOURCE_STUDIO_ROOT": str(PROJECT_ROOT)},
    )
    async with stdio_client(params) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            tools = await session.list_tools()
            tool_names = {tool.name for tool in tools.tools}
            assert "resource_studio.inspect_file" in tool_names
            assert "resource_studio.index_resources" in tool_names
            assert "resource_studio.apply_plan" in tool_names
            assert "resource_studio.read_audit" in tool_names

            resources = await session.list_resources()
            resource_uris = {str(resource.uri) for resource in resources.resources}
            assert "resource://workspace/info" in resource_uris
            templates = await session.list_resource_templates()
            template_uris = {template.uri_template for template in templates.resource_templates}
            assert "resource://file/{file_id}/manifest" in template_uris
            assert "resource://file/{file_id}/resource/{resource_key}" in template_uris
            prompts = await session.list_prompts()
            prompt_names = {prompt.name for prompt in prompts.prompts}
            assert {"review_change", "pe_triage"}.issubset(prompt_names)

            workspace = await session.read_resource("resource://workspace/info")
            workspace_text = workspace.contents[0].text
            workspace_payload = json.loads(workspace_text)
            assert workspace_payload["readOnly"] is True

            source_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
            registered = await session.call_tool(
                "resource_studio.register_file", {"path": str(FIXTURE)}
            )
            assert not registered.is_error
            registered_payload = registered.structured_content
            file_id = registered_payload["fileId"]
            assert registered_payload["sha256"] == source_hash
            manifest = await session.read_resource(registered_payload["manifestUri"])
            manifest_payload = json.loads(manifest.contents[0].text)
            assert manifest_payload["file"]["fileId"] == file_id

            inspected = await session.call_tool(
                "resource_studio.inspect_file", {"file_id": file_id}
            )
            assert not inspected.is_error
            inspected_payload = inspected.structured_content
            assert inspected_payload["readOnly"] is True
            assert inspected_payload["sha256"]

            indexed = await session.call_tool(
                "resource_studio.index_resources", {"file_id": file_id}
            )
            assert not indexed.is_error
            indexed_payload = indexed.structured_content
            assert indexed_payload["readOnly"] is True
            assert indexed_payload["resourceCount"] >= 0

            workspace_result = await session.call_tool(
                "resource_studio.create_workspace", {"file_id": file_id}
            )
            assert not workspace_result.is_error
            workspace_payload = workspace_result.structured_content
            assert workspace_payload["sourceSha256"] == source_hash
            workspace_path = Path(workspace_payload["workspacePath"])
            assert workspace_path.is_file()
            workspace_file = await session.call_tool(
                "resource_studio.register_file", {"path": str(workspace_path)}
            )
            assert not workspace_file.is_error
            workspace_file_id = workspace_file.structured_content["fileId"]
            assert workspace_path.read_bytes() == FIXTURE.read_bytes()
            workspace_hash_before_plan = hashlib.sha256(workspace_path.read_bytes()).hexdigest()

            diff = await session.call_tool(
                "resource_studio.diff_files",
                {"file_id_a": file_id, "file_id_b": workspace_file_id},
            )
            assert not diff.is_error
            diff_payload = diff.structured_content
            assert diff_payload["fileChanged"] is False

            resource = indexed_payload["resources"][0]
            assert resource["data_offset"] is not None
            resource_key = "/".join((str(resource["type"]), str(resource["name"]), str(resource["language"])))
            resource_uri = "resource://file/{}/resource/{}".format(file_id, quote(resource_key, safe=""))
            resource_document = await session.read_resource(resource_uri)
            resource_payload = json.loads(resource_document.contents[0].text)
            assert resource_payload["file"]["fileId"] == file_id
            assert resource_payload["resource"]["sha256"] == resource["sha256"]
            assert resource["size"] > 0
            payload_bytes = bytearray(FIXTURE.read_bytes()[resource["data_offset"] : resource["data_offset"] + resource["size"]])
            payload_bytes[0] ^= 0xFF
            PAYLOAD.write_bytes(payload_bytes)
            plan = await session.call_tool(
                "resource_studio.plan_resource_change",
                {
                    "workspace_id": workspace_payload["workspaceId"],
                    "operation": "replace",
                    "resource_type": str(resource["type"]),
                    "resource_name": str(resource["name"]),
                    "language": resource["language"],
                    "payload_path": str(PAYLOAD),
                },
            )
            assert not plan.is_error
            plan_payload = plan.structured_content
            assert plan_payload["writesFiles"] is False
            assert plan_payload["requiresConfirmation"] is True
            assert plan_payload["status"] == "planned"
            assert hashlib.sha256(workspace_path.read_bytes()).hexdigest() == workspace_hash_before_plan

            stored_plan = await session.call_tool(
                "resource_studio.get_plan", {"plan_id": plan_payload["planId"]}
            )
            review = await session.get_prompt("review_change", {"plan_id": plan_payload["planId"]})
            assert "Resource Studio plan" in review.messages[0].content.text
            assert not stored_plan.is_error
            assert stored_plan.structured_content["planId"] == plan_payload["planId"]
            assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == source_hash

            denied = await session.call_tool(
                "resource_studio.apply_plan",
                {
                    "plan_id": plan_payload["planId"],
                    "confirmation_token": plan_payload["confirmationToken"],
                    "confirmed": False,
                },
            )
            assert denied.is_error

            applied = await session.call_tool(
                "resource_studio.apply_plan",
                {
                    "plan_id": plan_payload["planId"],
                    "confirmation_token": plan_payload["confirmationToken"],
                    "confirmed": True,
                },
            )
            assert not applied.is_error
            applied_payload = applied.structured_content
            assert applied_payload["status"] == "verified"
            assert applied_payload["verification"]["reopened"] is True
            assert hashlib.sha256(workspace_path.read_bytes()).hexdigest() == workspace_hash_before_plan

            replay = await session.call_tool(
                "resource_studio.apply_plan",
                {
                    "plan_id": plan_payload["planId"],
                    "confirmation_token": plan_payload["confirmationToken"],
                    "confirmed": True,
                },
            )
            assert replay.is_error

            EXPORT.unlink(missing_ok=True)
            denied_export = await session.call_tool(
                "resource_studio.export_workspace",
                {
                    "plan_id": plan_payload["planId"],
                    "confirmation_token": applied_payload["exportConfirmationToken"],
                    "destination_path": str(EXPORT),
                    "confirmed": False,
                },
            )
            assert denied_export.is_error
            exported = await session.call_tool(
                "resource_studio.export_workspace",
                {
                    "plan_id": plan_payload["planId"],
                    "confirmation_token": applied_payload["exportConfirmationToken"],
                    "destination_path": str(EXPORT),
                    "confirmed": True,
                },
            )
            assert not exported.is_error
            exported_payload = exported.structured_content
            assert exported_payload["status"] == "verified"
            assert exported_payload["output"]["file"]["role"] == "exported_output"
            assert EXPORT.is_file()

            cancel_plan = await session.call_tool(
                "resource_studio.plan_resource_change",
                {
                    "workspace_id": workspace_payload["workspaceId"],
                    "operation": "replace",
                    "resource_type": str(resource["type"]),
                    "resource_name": str(resource["name"]),
                    "language": resource["language"],
                    "payload_path": str(PAYLOAD),
                },
            )
            assert not cancel_plan.is_error
            cancelled = await session.call_tool(
                "resource_studio.cancel_plan", {"plan_id": cancel_plan.structured_content["planId"]}
            )
            assert not cancelled.is_error
            assert cancelled.structured_content["status"] == "cancelled"

            audit = await session.call_tool(
                "resource_studio.read_audit",
                {"operation_id": applied_payload["operationId"]},
            )
            assert not audit.is_error
            assert audit.structured_content["verified"] is True
            assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == source_hash
            export_audit = await session.call_tool(
                "resource_studio.read_audit", {"operation_id": exported_payload["operationId"]}
            )
            assert not export_audit.is_error
            assert export_audit.structured_content["operation"] == "export"
            Path(applied_payload["outputPath"]).unlink(missing_ok=True)
            EXPORT.unlink(missing_ok=True)
            PAYLOAD.unlink(missing_ok=True)
            shutil.rmtree(workspace_path.parent, ignore_errors=True)

            outside = await session.call_tool(
                "resource_studio.inspect_file", {"path": "/etc/hosts"}
            )
            assert outside.is_error

            non_pe = await session.call_tool(
                "resource_studio.inspect_file", {"path": str(NON_PE)}
            )
            assert not non_pe.is_error
            non_pe_payload = non_pe.structured_content
            assert non_pe_payload["pe"]["is_pe"] is False
            assert non_pe_payload["warnings"]

            print(
                json.dumps(
                    {
                        "status": "passed",
                        "tools": sorted(tool_names),
                        "resources": sorted(resource_uris),
                        "resourceTemplates": sorted(template_uris),
                        "prompts": sorted(prompt_names),
                        "resourceCount": indexed_payload["resourceCount"],
                        "planStatus": plan_payload["status"],
                        "fileId": file_id,
                    },
                    sort_keys=True,
                )
            )


if __name__ == "__main__":
    anyio.run(main)

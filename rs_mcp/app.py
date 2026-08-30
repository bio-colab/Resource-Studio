"""The singleton MCP server instance every handler module registers onto."""
from mcp.server import MCPServer

server = MCPServer(
    "resource-studio",
    version="0.2.0",
    title="Resource Studio MCP",
    description="PE and Win32 resource inspection with isolated workspaces and dry-run plans.",
    instructions=(
        "Inspection and indexing are read-only. Workspace creation copies a source into an "
        "internal isolated directory. Planning never changes the source or workspace file. "
        "Apply is limited to confirmed same-size replacement in the workspace copy."
    ),
    log_level="INFO",
)

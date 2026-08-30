"""Resource Studio MCP implementation package.

Lives outside the repository-local `mcp/` directory on purpose: the installed
MCP SDK is imported as `mcp`, and the local `mcp/` folder intentionally has no
`__init__.py` so it never shadows the SDK. `mcp/server.py` stays the executable
composition root; this package holds the implementation modules.
"""

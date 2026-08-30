"""Resource Studio MCP composition root.

The MCP SDK is installed as the `mcp` package while this repository keeps its
own `mcp/` directory; the local directory intentionally has no `__init__.py`
so the installed SDK keeps winning `import mcp`. This file stays the executable
and import entry (clients and tests load it by path) and delegates the
implementation to the top-level `rs_mcp` package:
state/pemodel/files/workspaces hold the shared layers, handlers_* modules
register the tool/resource/prompt surface onto the server instance at import
time, and the calls below restore persisted state and discover plugins exactly
like the previous single-file server did after registration.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rs_mcp import plugins as _plugins
from rs_mcp.app import server
from rs_mcp.handlers_discovery import (  # noqa: F401
    file_manifest,
    file_resource,
    operation_audit,
    pe_triage,
    plan_resource,
    plugins_resource,
    register_file,
    review_change,
    session_events,
    session_state,
    tools_metadata,
    workspace_info,
    workspace_resource,
)
from rs_mcp.handlers_integrations import (  # noqa: F401
    apply_integration_request,
    list_integrations,
    plan_integration_request,
)
from rs_mcp.handlers_live import (  # noqa: F401
    import_live_analysis,
    live_analysis_contract,
    live_analysis_report_resource,
    live_analysis_session_resource,
    start_live_analysis_session,
)
from rs_mcp.handlers_package import (  # noqa: F401
    apply_package_change_tool,
    inspect_package_tool,
    plan_package_change,
)
from rs_mcp.handlers_plugins import (  # noqa: F401
    apply_plugin_execution,
    enable_plugin,
    inspect_plugin,
    list_plugins,
    plan_plugin_execution,
)
from rs_mcp.handlers_readonly import index_resources, inspect_file  # noqa: F401
from rs_mcp.handlers_workspace import (  # noqa: F401
    apply_plan,
    cancel_plan,
    create_workspace,
    diff_files,
    export_workspace,
    get_plan,
    plan_resource_change,
    read_audit,
)
from rs_mcp.state import LOGGER, ROOT, _load_state  # noqa: F401

_load_state()
_plugins._discover_plugins()

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    LOGGER.info("starting Resource Studio MCP stdio server; root=%s", ROOT)
    server.run("stdio")

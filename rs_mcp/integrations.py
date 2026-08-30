"""External integration registry and gateway singletons."""
from core.external_integrations import IntegrationGateway, IntegrationRegistry

from rs_mcp.state import STATE_ROOT

INTEGRATION_REGISTRY = IntegrationRegistry(STATE_ROOT / "integrations.json")
INTEGRATION_GATEWAY = IntegrationGateway(INTEGRATION_REGISTRY)



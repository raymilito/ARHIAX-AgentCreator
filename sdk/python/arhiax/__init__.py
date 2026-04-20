"""ARHIAX SDK — Crea agentes gobernados bajo estándar ARHIAX.

Uso rápido:
    from arhiax import ARHIAXAgent, governed_tool

    class MiAgente(ARHIAXAgent):
        agent_id = "agent-abc123"
        gateway_url = "http://localhost:8080"

        @governed_tool(resource="buscar")
        async def buscar(self, query: str) -> list:
            ...
"""
from .agent import ARHIAXAgent, governed_tool
from .client import AIMClient, BBRClient, GatewayClient, HICClient
from .exceptions import (
    ARHIAXCredentialExpired,
    ARHIAXDenied,
    ARHIAXError,
    ARHIAXEscalated,
    ARHIAXInjectionDetected,
    ARHIAXServiceUnavailable,
    ARHIAXToolNotPermitted,
)
from .models import (
    Credential,
    DecisionOutcome,
    GovernanceDecision,
    AutonomyLevel,
)

__version__ = "1.0.0"
__all__ = [
    "ARHIAXAgent",
    "governed_tool",
    "GatewayClient",
    "AIMClient",
    "HICClient",
    "BBRClient",
    "ARHIAXError",
    "ARHIAXDenied",
    "ARHIAXEscalated",
    "ARHIAXInjectionDetected",
    "ARHIAXCredentialExpired",
    "ARHIAXServiceUnavailable",
    "ARHIAXToolNotPermitted",
    "Credential",
    "GovernanceDecision",
    "DecisionOutcome",
    "AutonomyLevel",
]

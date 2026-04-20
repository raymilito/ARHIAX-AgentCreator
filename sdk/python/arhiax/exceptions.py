"""Excepciones del SDK ARHIAX."""
from __future__ import annotations

from typing import List


class ARHIAXError(Exception):
    """Base de todas las excepciones ARHIAX."""


class ARHIAXDenied(ARHIAXError):
    """Acción bloqueada por política de gobernanza."""

    def __init__(self, action: str, resource: str, reasons: List[str], evidence_id: str = ""):
        self.action = action
        self.resource = resource
        self.reasons = reasons
        self.evidence_id = evidence_id
        super().__init__(
            f"Acción '{action}' sobre '{resource}' bloqueada. Razones: {', '.join(reasons) or 'sin detalle'}. "
            f"Evidencia: {evidence_id}"
        )


class ARHIAXEscalated(ARHIAXError):
    """Acción escalada a revisión humana — bloqueada hasta aprobación."""

    def __init__(self, action: str, resource: str, ticket_id: str = ""):
        self.action = action
        self.resource = resource
        self.ticket_id = ticket_id
        super().__init__(
            f"Acción '{action}' sobre '{resource}' requiere aprobación humana. "
            f"Ticket HIC: {ticket_id or 'sin ticket'}"
        )


class ARHIAXInjectionDetected(ARHIAXError):
    """Patrón de inyección detectado en el input del agente."""

    def __init__(self, evidence_id: str = ""):
        self.evidence_id = evidence_id
        super().__init__(f"Inyección detectada en el input. Incidente registrado: {evidence_id}")


class ARHIAXCredentialExpired(ARHIAXError):
    """Credencial del agente expirada o revocada."""

    def __init__(self, agent_id: str, lifecycle_state: str):
        self.agent_id = agent_id
        self.lifecycle_state = lifecycle_state
        super().__init__(f"Credencial del agente {agent_id} está en estado {lifecycle_state}")


class ARHIAXServiceUnavailable(ARHIAXError):
    """Servicio ARHIAX no disponible (Gateway, OPA, etc.)."""

    def __init__(self, service: str, detail: str = ""):
        self.service = service
        super().__init__(f"Servicio ARHIAX '{service}' no disponible. {detail}")


class ARHIAXToolNotPermitted(ARHIAXError):
    """Herramienta no autorizada para este agente."""

    def __init__(self, agent_id: str, tool_name: str, permitted: list):
        self.agent_id = agent_id
        self.tool_name = tool_name
        super().__init__(
            f"Herramienta '{tool_name}' no autorizada para agente {agent_id}. "
            f"Herramientas permitidas: {permitted}"
        )

"""Modelos de datos compartidos del SDK ARHIAX."""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class AutonomyLevel(str, Enum):
    A0 = "A0"  # Inerte — toda acción requiere aprobación
    A1 = "A1"  # Supervisado — alto impacto requiere aprobación
    A2 = "A2"  # Guiado — impacto medio requiere aprobación
    A3 = "A3"  # Autónomo — solo crítico requiere aprobación
    A4 = "A4"  # Adaptativo — solo excepciones


class LifecycleState(str, Enum):
    ACTIVE = "ACTIVE"
    ROTATING = "ROTATING"
    SUSPENDED = "SUSPENDED"
    RETIRED = "RETIRED"


class DecisionOutcome(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_MONITORING = "ALLOW_WITH_MONITORING"
    ALLOW_WITH_HIC_NOTIFICATION = "ALLOW_WITH_HIC_NOTIFICATION"
    DENY = "DENY"
    DENY_WITH_INCIDENT = "DENY_WITH_INCIDENT"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"


class Credential(BaseModel):
    agent_id: str
    name: str = ""
    supervisor_id: str
    department_id: str
    authorization_boundary_id: str
    autonomy_level: str
    credential_issued_at: str
    credential_expires_at: str
    rotation_policy: str
    lifecycle_state: str
    parent_chain_hmac: str
    permitted_tools: List[str] = []
    permitted_data_scopes: List[str] = []
    permitted_operations: List[str] = []


class GovernanceDecision(BaseModel):
    allow: bool
    outcome: DecisionOutcome
    reasons: List[str] = []
    obligations: List[Dict[str, Any]] = []
    evidence_id: str = ""
    hic_ticket_id: Optional[str] = None

    @property
    def is_allowed(self) -> bool:
        return self.allow

    @property
    def requires_human(self) -> bool:
        return self.outcome in (
            DecisionOutcome.ALLOW_WITH_HIC_NOTIFICATION,
            DecisionOutcome.ESCALATE_TO_HUMAN,
        )

    @property
    def is_blocked(self) -> bool:
        return self.outcome in (
            DecisionOutcome.DENY,
            DecisionOutcome.DENY_WITH_INCIDENT,
            DecisionOutcome.ESCALATE_TO_HUMAN,
        )


class ToolCallContext(BaseModel):
    tool_name: str
    params: Dict[str, Any] = {}
    invocation_id: str = ""
    requested_autonomy_level: str = "A1"


class ModelInvokeContext(BaseModel):
    prompt: str
    model: str = "claude-sonnet-4-6"
    system_prompt: str = ""
    invocation_id: str = ""
    requested_autonomy_level: str = "A1"

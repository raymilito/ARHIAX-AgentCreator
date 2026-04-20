"""Tests de los modelos Pydantic del SDK ARHIAX."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arhiax.models import (
    AutonomyLevel, LifecycleState, DecisionOutcome,
    Credential, GovernanceDecision,
)


# ── AutonomyLevel ─────────────────────────────────────────────────────────────

def test_autonomy_level_values():
    assert AutonomyLevel.A0 == "A0"
    assert AutonomyLevel.A4 == "A4"


def test_autonomy_level_order():
    levels = [AutonomyLevel.A0, AutonomyLevel.A1, AutonomyLevel.A2,
              AutonomyLevel.A3, AutonomyLevel.A4]
    assert len(levels) == 5


# ── LifecycleState ────────────────────────────────────────────────────────────

def test_lifecycle_state_all():
    assert LifecycleState.ACTIVE    == "ACTIVE"
    assert LifecycleState.ROTATING  == "ROTATING"
    assert LifecycleState.SUSPENDED == "SUSPENDED"
    assert LifecycleState.RETIRED   == "RETIRED"


# ── DecisionOutcome ───────────────────────────────────────────────────────────

def test_decision_outcome_all_six():
    outcomes = [
        DecisionOutcome.ALLOW,
        DecisionOutcome.ALLOW_WITH_MONITORING,
        DecisionOutcome.ALLOW_WITH_HIC_NOTIFICATION,
        DecisionOutcome.DENY,
        DecisionOutcome.DENY_WITH_INCIDENT,
        DecisionOutcome.ESCALATE_TO_HUMAN,
    ]
    assert len(outcomes) == 6


# ── Credential ────────────────────────────────────────────────────────────────

CRED_DATA = {
    "agent_id": "agent-test-001",
    "name": "AgenteTest",
    "supervisor_id": "sup-001",
    "department_id": "dept-test",
    "authorization_boundary_id": "default",
    "autonomy_level": "A0",
    "credential_issued_at": "2026-04-19T12:00:00",
    "credential_expires_at": "2026-07-18T12:00:00",
    "rotation_policy": "90d",
    "lifecycle_state": "ACTIVE",
    "parent_chain_hmac": "sha256:abc123",
    "permitted_tools": ["consultar_db", "generar_reporte"],
    "permitted_data_scopes": ["analytics"],
    "permitted_operations": ["modelInvoke", "toolCall"],
}


def test_credential_parse():
    cred = Credential(**CRED_DATA)
    assert cred.agent_id == "agent-test-001"
    assert cred.autonomy_level == "A0"
    assert "consultar_db" in cred.permitted_tools


def test_credential_defaults():
    cred = Credential(**{k: v for k, v in CRED_DATA.items()
                         if k not in ("permitted_tools", "permitted_data_scopes", "permitted_operations")})
    assert cred.permitted_tools == []
    assert cred.permitted_operations == []


# ── GovernanceDecision ────────────────────────────────────────────────────────

def _make_decision(outcome: DecisionOutcome, allow: bool = True) -> GovernanceDecision:
    return GovernanceDecision(
        allow=allow,
        outcome=outcome,
        reasons=[],
        obligations=[],
        evidence_id="ev-001",
    )


def test_decision_allow_properties():
    d = _make_decision(DecisionOutcome.ALLOW)
    assert d.is_allowed is True
    assert d.requires_human is False
    assert d.is_blocked is False


def test_decision_allow_with_monitoring():
    d = _make_decision(DecisionOutcome.ALLOW_WITH_MONITORING)
    assert d.is_allowed is True
    assert d.requires_human is False
    assert d.is_blocked is False


def test_decision_allow_with_hic():
    d = _make_decision(DecisionOutcome.ALLOW_WITH_HIC_NOTIFICATION)
    assert d.is_allowed is True
    assert d.requires_human is True
    assert d.is_blocked is False


def test_decision_deny():
    d = _make_decision(DecisionOutcome.DENY, allow=False)
    assert d.is_allowed is False
    assert d.requires_human is False
    assert d.is_blocked is True


def test_decision_deny_with_incident():
    d = _make_decision(DecisionOutcome.DENY_WITH_INCIDENT, allow=False)
    assert d.is_allowed is False
    assert d.is_blocked is True


def test_decision_escalate_to_human():
    d = _make_decision(DecisionOutcome.ESCALATE_TO_HUMAN, allow=False)
    assert d.is_allowed is False
    assert d.requires_human is True
    assert d.is_blocked is True

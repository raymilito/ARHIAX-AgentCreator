"""Tests del flujo bloqueante de step-up via HIC en ARHIAXAgent."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from arhiax.agent import ARHIAXAgent, governed_tool
from arhiax.exceptions import ARHIAXEscalated
from arhiax.models import (
    DecisionOutcome,
    EphemeralToolToken,
    GovernanceDecision,
)


def _make_agent(decisions, ticket_status, *, severity="HIGH"):
    """Crea un agente con mocks deterministicos para el flujo HIC."""

    class _Agent(ARHIAXAgent):
        agent_id = "agent-hic-test"
        gateway_url = "http://gw"
        aim_url = "http://aim"
        hic_url = "http://hic"
        bbr_url = "http://bbr"
        credential_broker_url = "http://broker"

        @governed_tool(action="toolCall", resource="op_sensible", severity=severity)
        async def op_sensible(self, payload: str) -> str:
            return f"ok:{payload}"

    agent = _Agent(security_profile={
        "hic_poll_interval_seconds": 0.01,
        "hic_poll_timeout_seconds": 1.0,
        "enforce_broker_for_tools": False,
    })
    agent._gateway.decide = AsyncMock(side_effect=decisions)
    agent._hic.open_ticket = AsyncMock(return_value="hic-1")
    agent._hic.get_ticket_status = AsyncMock(return_value=ticket_status)
    agent._bbr.record_observation = AsyncMock(return_value=None)
    return agent


def _decision(outcome: DecisionOutcome, reasons=None, ev="ev-1"):
    return GovernanceDecision(
        allow=outcome == DecisionOutcome.ALLOW,
        outcome=outcome,
        reasons=reasons or [],
        evidence_id=ev,
    )


@pytest.mark.asyncio
async def test_step_up_approved_unlocks_tool():
    # Primer decide: escalate. Segundo decide (tras HIC APPROVED + reevaluacion): allow.
    decisions = [
        _decision(DecisionOutcome.ESCALATE_TO_HUMAN, ["STEP_UP_REQUIRED"]),
        _decision(DecisionOutcome.ALLOW),
    ]
    agent = _make_agent(decisions, "APPROVED")
    result = await agent.op_sensible(payload="x")
    assert result == "ok:x"
    # HIC abierto exactamente una vez, poll consultado >= 1 vez
    agent._hic.open_ticket.assert_awaited_once()
    assert agent._hic.get_ticket_status.await_count >= 1
    # Segundo decide debio llevar step_up_satisfied=True
    second_call = agent._gateway.decide.call_args_list[1]
    assert second_call.kwargs["context"]["step_up_satisfied"] is True


@pytest.mark.asyncio
async def test_step_up_rejected_raises_escalated():
    decisions = [_decision(DecisionOutcome.ESCALATE_TO_HUMAN, ["STEP_UP_REQUIRED"])]
    agent = _make_agent(decisions, "REJECTED")
    with pytest.raises(ARHIAXEscalated):
        await agent.op_sensible(payload="x")
    # No hubo segundo decide
    assert agent._gateway.decide.await_count == 1


@pytest.mark.asyncio
async def test_step_up_timeout_treated_as_rejection():
    decisions = [_decision(DecisionOutcome.ESCALATE_TO_HUMAN, ["STEP_UP_REQUIRED"])]
    agent = _make_agent(decisions, "PENDING")
    agent.security_profile.hic_poll_timeout_seconds = 0.05
    agent.security_profile.hic_poll_interval_seconds = 0.01
    with pytest.raises(ARHIAXEscalated):
        await agent.op_sensible(payload="x")


@pytest.mark.asyncio
async def test_dual_approval_passed_for_critical():
    decisions = [
        _decision(DecisionOutcome.ESCALATE_TO_HUMAN, ["DUAL_APPROVAL_REQUIRED"]),
        _decision(DecisionOutcome.ALLOW),
    ]
    agent = _make_agent(decisions, "APPROVED", severity="CRITICAL")
    await agent.op_sensible(payload="x")
    second = agent._gateway.decide.call_args_list[1]
    ctx = second.kwargs["context"]
    assert ctx["step_up_satisfied"] is True
    assert ctx["dual_approval_ticket_id"] == "hic-1"


@pytest.mark.asyncio
async def test_step_up_disabled_propagates_escalate():
    decisions = [_decision(DecisionOutcome.ESCALATE_TO_HUMAN, ["STEP_UP_REQUIRED"])]
    agent = _make_agent(decisions, "APPROVED")
    agent.security_profile.enable_hic_step_up = False
    with pytest.raises(ARHIAXEscalated):
        await agent.op_sensible(payload="x")
    # HIC no se debio abrir
    agent._hic.open_ticket.assert_not_awaited()

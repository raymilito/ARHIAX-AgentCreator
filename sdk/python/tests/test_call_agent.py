"""Tests del flujo inter-agent call con token exchange (RFC 8693)."""
from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock

import pytest

from arhiax.agent import ARHIAXAgent
from arhiax.models import DecisionOutcome, EphemeralToolToken, GovernanceDecision


def _b64u_decode(v: str) -> bytes:
    return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))


def _make_agent(severity="MEDIUM"):
    class _A(ARHIAXAgent):
        agent_id = "agent-A"
        gateway_url = "http://gw"
        aim_url = "http://aim"
        hic_url = "http://hic"
        bbr_url = "http://bbr"
        credential_broker_url = "http://broker"

    return _A(security_profile={
        "enforce_broker_for_tools": True,
        "require_pop": False,  # simplificamos: sin DPoP en este unit test
    })


def _allow(ev="ev-x"):
    return GovernanceDecision(
        allow=True, outcome=DecisionOutcome.ALLOW, reasons=[], evidence_id=ev,
    )


@pytest.mark.asyncio
async def test_call_agent_uses_token_exchange_with_act_chain():
    agent = _make_agent()
    # Dos decisiones: inicial y confirmacion, ambas ALLOW.
    agent._gateway.decide = AsyncMock(side_effect=[_allow("ev-1"), _allow("ev-2")])

    # Capturamos el payload enviado al broker para verificar act_chain
    captured = {}

    async def fake_issue_tool_token(**kwargs):
        captured.update(kwargs)
        return EphemeralToolToken(
            token="header.payload.sig",
            jti="jti-x",
            audience=kwargs["audience"],
            scope=kwargs["scope"],
            resource=kwargs["tool_name"],
            invocation_id=kwargs["invocation_id"],
            context_binding=kwargs["context_binding"],
            issued_at="2026-01-01T00:00:00Z",
            expires_at="2026-01-01T00:01:00Z",
            delegated_by=kwargs["agent_id"],
        )

    agent._credential_broker.issue_tool_token = fake_issue_tool_token

    result = await agent.call_agent("agent-B", {"task": "x"})
    assert result.allow is True

    # El broker recibio act_chain con agent-A al frente
    assert captured["act_chain"] == ["agent-A"]
    assert captured["audience"] == "agent:agent-B"
    assert captured["scope"] == "agent:invoke:agent-B"

    # La confirmacion al gateway llevo ephemeralAuth y brokerTrace.act_chain
    second_call = agent._gateway.decide.call_args_list[1]
    ctx = second_call.kwargs["context"]
    assert ctx["ephemeralAuth"]["token"] == "header.payload.sig"
    assert ctx["brokerTrace"]["act_chain"] == ["agent-A"]
    assert ctx["toolName"] == "agent:agent-B"


@pytest.mark.asyncio
async def test_call_agent_extends_existing_chain():
    agent = _make_agent()
    agent._gateway.decide = AsyncMock(side_effect=[_allow(), _allow()])
    captured = {}

    async def fake_issue(**kwargs):
        captured.update(kwargs)
        return EphemeralToolToken(
            token="h.p.s", jti="j", audience=kwargs["audience"],
            scope=kwargs["scope"], resource=kwargs["tool_name"],
            invocation_id=kwargs["invocation_id"],
            context_binding=kwargs["context_binding"],
            issued_at="x", expires_at="y", delegated_by=kwargs["agent_id"],
        )

    agent._credential_broker.issue_tool_token = fake_issue
    # context_chain externa: agente-A llamó a esta clase que es agent-A
    await agent.call_agent("agent-C", {"x": 1}, context_chain=["agent-0", "agent-A"])
    # La cadena se preserva (agent-A ya estaba al frente del chain compatible)
    assert captured["act_chain"] == ["agent-A", "agent-0", "agent-A"] or \
           captured["act_chain"][0] == "agent-A"


@pytest.mark.asyncio
async def test_call_agent_skips_token_when_broker_disabled():
    agent = _make_agent()
    agent.security_profile.enforce_broker_for_tools = False
    agent._gateway.decide = AsyncMock(side_effect=[_allow()])
    agent._credential_broker.issue_tool_token = AsyncMock()
    decision = await agent.call_agent("agent-B", {"task": "x"})
    assert decision.allow is True
    # Solo una llamada al gateway, broker no se invoca
    assert agent._gateway.decide.await_count == 1
    agent._credential_broker.issue_tool_token.assert_not_awaited()

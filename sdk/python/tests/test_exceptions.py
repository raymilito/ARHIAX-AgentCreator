"""Tests de las excepciones tipadas del SDK ARHIAX."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arhiax.exceptions import (
    ARHIAXError, ARHIAXDenied, ARHIAXEscalated,
    ARHIAXInjectionDetected, ARHIAXCredentialExpired,
    ARHIAXServiceUnavailable, ARHIAXToolNotPermitted,
)


# ── Jerarquía ─────────────────────────────────────────────────────────────────

def test_all_inherit_from_base():
    for exc_class in [ARHIAXDenied, ARHIAXEscalated, ARHIAXInjectionDetected,
                      ARHIAXCredentialExpired, ARHIAXServiceUnavailable, ARHIAXToolNotPermitted]:
        assert issubclass(exc_class, ARHIAXError)
        assert issubclass(exc_class, Exception)


# ── ARHIAXDenied ──────────────────────────────────────────────────────────────

def test_denied_attributes():
    exc = ARHIAXDenied("delete", "tabla-critica", ["POLICY_DENY", "LOW_AUTONOMY"], "ev-001")
    assert exc.action == "delete"
    assert exc.resource == "tabla-critica"
    assert "POLICY_DENY" in exc.reasons
    assert exc.evidence_id == "ev-001"


def test_denied_message_contains_action():
    exc = ARHIAXDenied("transfer_funds", "cuenta-123", ["AUTONOMY_INSUFFICIENT"])
    assert "transfer_funds" in str(exc)
    assert "cuenta-123" in str(exc)


def test_denied_no_evidence_id():
    exc = ARHIAXDenied("toolCall", "db", ["DENY"])
    assert exc.evidence_id == ""


def test_denied_empty_reasons():
    exc = ARHIAXDenied("toolCall", "db", [])
    assert exc.reasons == []
    assert "sin detalle" in str(exc)


def test_denied_catchable_as_base():
    with pytest.raises(ARHIAXError):
        raise ARHIAXDenied("delete", "db", ["DENY"])


# ── ARHIAXEscalated ───────────────────────────────────────────────────────────

def test_escalated_attributes():
    exc = ARHIAXEscalated("deploy", "prod-server", "hic-a1b2c3")
    assert exc.action == "deploy"
    assert exc.resource == "prod-server"
    assert exc.ticket_id == "hic-a1b2c3"


def test_escalated_message_contains_ticket():
    exc = ARHIAXEscalated("override_safety", "system", "hic-xyz")
    assert "hic-xyz" in str(exc)


def test_escalated_no_ticket():
    exc = ARHIAXEscalated("deploy", "server")
    assert exc.ticket_id == ""
    assert "sin ticket" in str(exc)


# ── ARHIAXInjectionDetected ───────────────────────────────────────────────────

def test_injection_attributes():
    exc = ARHIAXInjectionDetected("ev-9999999999")
    assert exc.evidence_id == "ev-9999999999"


def test_injection_no_evidence():
    exc = ARHIAXInjectionDetected()
    assert exc.evidence_id == ""


def test_injection_catchable_as_base():
    with pytest.raises(ARHIAXError):
        raise ARHIAXInjectionDetected("ev-001")


# ── ARHIAXCredentialExpired ───────────────────────────────────────────────────

def test_credential_expired_attributes():
    exc = ARHIAXCredentialExpired("agent-abc", "SUSPENDED")
    assert exc.agent_id == "agent-abc"
    assert exc.lifecycle_state == "SUSPENDED"


def test_credential_retired_state():
    exc = ARHIAXCredentialExpired("agent-xyz", "RETIRED")
    assert "RETIRED" in str(exc)


# ── ARHIAXServiceUnavailable ──────────────────────────────────────────────────

def test_service_unavailable_attributes():
    exc = ARHIAXServiceUnavailable("Gateway", "Circuit breaker OPEN")
    assert exc.service == "Gateway"
    assert "Gateway" in str(exc)
    assert "Circuit breaker" in str(exc)


def test_service_unavailable_no_detail():
    exc = ARHIAXServiceUnavailable("OPA")
    assert "OPA" in str(exc)


# ── ARHIAXToolNotPermitted ────────────────────────────────────────────────────

def test_tool_not_permitted_attributes():
    exc = ARHIAXToolNotPermitted("agent-001", "borrar_db", ["consultar_db", "leer_docs"])
    assert exc.agent_id == "agent-001"
    assert exc.tool_name == "borrar_db"


def test_tool_not_permitted_message():
    exc = ARHIAXToolNotPermitted("agent-001", "borrar_db", ["consultar_db"])
    assert "borrar_db" in str(exc)
    assert "consultar_db" in str(exc)


# ── Captura polimórfica ───────────────────────────────────────────────────────

def test_catch_all_as_arhiax_error():
    exceptions = [
        ARHIAXDenied("a", "b", []),
        ARHIAXEscalated("a", "b"),
        ARHIAXInjectionDetected(),
        ARHIAXCredentialExpired("a", "SUSPENDED"),
        ARHIAXServiceUnavailable("X"),
        ARHIAXToolNotPermitted("a", "t", []),
    ]
    for exc in exceptions:
        with pytest.raises(ARHIAXError):
            raise exc

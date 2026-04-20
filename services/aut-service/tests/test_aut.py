"""Tests unitarios del AUT Service."""
import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    os.environ["AUT_DB_PATH"] = str(tmp_path / "aut.db")
    from main import init_db
    init_db()
    yield

@pytest.fixture
def client():
    from main import app
    return TestClient(app)


def _register(client, agent_id="agent-test-001"):
    """Registra un agente en A0 vía el endpoint interno."""
    r = client.post("/v1/autonomy/register", json={"agent_id": agent_id})
    return r


# ── Health ────────────────────────────────────────────────────────────────────

def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200


# ── Registro inicial ──────────────────────────────────────────────────────────

def test_register_initializes_a0(client):
    r = _register(client)
    assert r.status_code in (200, 201)
    data = r.json()
    assert data["current_level"] == "A0"
    assert data["sigma_threshold"] == 1.5


def test_get_autonomy_not_found(client):
    r = client.get("/v1/autonomy/agent-no-existe")
    assert r.status_code == 404


def test_get_autonomy_ok(client):
    _register(client)
    r = client.get("/v1/autonomy/agent-test-001")
    assert r.status_code == 200
    assert r.json()["current_level"] == "A0"


# ── Check de acción ───────────────────────────────────────────────────────────

def test_check_action_allow_within_threshold(client):
    _register(client)
    r = client.post("/v1/autonomy/check", json={
        "agent_id": "agent-test-001",
        "action": "consultar_datos",
        "requested_level": "A0",
        "sigma_deviation": 0.5,
    })
    assert r.status_code == 200
    data = r.json()
    assert data["allowed"] is True


def test_check_action_deny_sigma_exceeded(client):
    _register(client)
    r = client.post("/v1/autonomy/check", json={
        "agent_id": "agent-test-001",
        "action": "consultar_datos",
        "requested_level": "A0",
        "sigma_deviation": 9.0,  # supera 1.5σ de A0
    })
    assert r.status_code == 200
    data = r.json()
    assert data["allowed"] is False
    assert "ESCALATE" in data["outcome"] or data["requires_hil"] is True


def test_check_action_high_impact_requires_hil(client):
    _register(client)
    r = client.post("/v1/autonomy/check", json={
        "agent_id": "agent-test-001",
        "action": "delete",
        "requested_level": "A0",
        "sigma_deviation": 0.0,
    })
    assert r.status_code == 200
    assert r.json()["requires_hil"] is True


def test_check_action_agent_not_found(client):
    r = client.post("/v1/autonomy/check", json={
        "agent_id": "agente-fantasma",
        "action": "consultar",
        "requested_level": "A0",
        "sigma_deviation": 0.0,
    })
    assert r.status_code == 404


# ── Promoción ─────────────────────────────────────────────────────────────────

def test_promote_all_gates_true(client):
    _register(client)
    r = client.post("/v1/autonomy/agent-test-001/promote", json={
        "agent_id": "agent-test-001",
        "target_level": "A1",
        "gates": {
            "G1_performance": True,
            "G2_security": True,
            "G3_business": True,
            "G4_history": True,
            "G5_governance": True,
        },
        "justification": "30 días operación limpia",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["promoted"] is True
    assert data["new_level"] == "A1"


def test_promote_gates_failed(client):
    _register(client)
    r = client.post("/v1/autonomy/agent-test-001/promote", json={
        "agent_id": "agent-test-001",
        "target_level": "A1",
        "gates": {
            "G1_performance": True,
            "G2_security": False,   # falla
            "G3_business": True,
            "G4_history": False,    # falla
            "G5_governance": True,
        },
        "justification": "",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["promoted"] is False
    assert "G2_security" in data["failed_gates"]
    assert "G4_history" in data["failed_gates"]


def test_promote_skip_level_denied(client):
    """No se puede saltar de A0 directamente a A2."""
    _register(client)
    r = client.post("/v1/autonomy/agent-test-001/promote", json={
        "agent_id": "agent-test-001",
        "target_level": "A2",
        "gates": {k: True for k in ["G1_performance","G2_security","G3_business","G4_history","G5_governance"]},
        "justification": "",
    })
    assert r.status_code in (400, 200)
    if r.status_code == 200:
        assert r.json()["promoted"] is False


# ── Degradación ───────────────────────────────────────────────────────────────

def test_degrade_from_a1_to_a0(client):
    _register(client)
    # Primero promover a A1
    client.post("/v1/autonomy/agent-test-001/promote", json={
        "agent_id": "agent-test-001",
        "target_level": "A1",
        "gates": {k: True for k in ["G1_performance","G2_security","G3_business","G4_history","G5_governance"]},
        "justification": "test",
    })
    r = client.post("/v1/autonomy/agent-test-001/degrade", json={
        "agent_id": "agent-test-001",
        "reason": "Sigma excedido",
        "sigma_observed": 3.5,
    })
    assert r.status_code == 200
    assert r.json()["new_level"] == "A0"


def test_degrade_already_at_a0(client):
    _register(client)
    r = client.post("/v1/autonomy/agent-test-001/degrade", json={
        "agent_id": "agent-test-001",
        "reason": "Test floor",
        "sigma_observed": 2.0,
    })
    assert r.status_code == 200
    assert r.json()["new_level"] == "A0"


# ── Historial ─────────────────────────────────────────────────────────────────

def test_history_after_promotion_and_demotion(client):
    _register(client)
    client.post("/v1/autonomy/agent-test-001/promote", json={
        "agent_id": "agent-test-001",
        "target_level": "A1",
        "gates": {k: True for k in ["G1_performance","G2_security","G3_business","G4_history","G5_governance"]},
        "justification": "test",
    })
    client.post("/v1/autonomy/agent-test-001/degrade", json={
        "agent_id": "agent-test-001",
        "reason": "Sigma alto",
        "sigma_observed": 5.0,
    })
    r = client.get("/v1/autonomy/agent-test-001/history")
    assert r.status_code == 200
    events = r.json()
    assert len(events) >= 2
    types = [e["event_type"] for e in events]
    assert "PROMOTE" in types
    assert "DEGRADE" in types

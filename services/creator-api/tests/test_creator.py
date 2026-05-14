"""Tests unitarios del Creator API.

Todos los servicios upstream (AIM, AUT, Gateway) están mockeados con httpx.
"""
import os
import sys
import copy
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

os.environ["AIM_URL"]     = "http://aim-mock:8200"
os.environ["AUT_URL"]     = "http://aut-mock:8201"
os.environ["GATEWAY_URL"] = "http://gw-mock:8080"
os.environ["HIC_URL"]     = "http://hic-mock:8203"

SERVICE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, SERVICE_DIR)
sys.modules.pop("main", None)


MOCK_CREDENTIAL = {
    "agent_id": "agent-abc123",
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
    "permitted_tools": ["consultar_datos"],
    "permitted_data_scopes": [],
    "permitted_operations": ["modelInvoke", "toolCall"],
}

MOCK_AUTONOMY = {
    "agent_id": "agent-abc123",
    "current_level": "A0",
    "sigma_threshold": 1.5,
    "effective_since": "2026-04-19T12:00:00",
}

AGENT_SPEC = {
    "name": "AgenteTest",
    "department_id": "dept-test",
    "supervisor_id": "sup-001",
    "permitted_tools": ["consultar_datos"],
}


def _mock_upstream():
    """Contexto que mockea AIM y AUT para creación exitosa."""
    async def fake_post(url, data):
        if "register" in url:
            return copy.deepcopy(MOCK_CREDENTIAL)
        if "autonomy" in url:
            return copy.deepcopy(MOCK_AUTONOMY)
        return {}

    async def fake_get(url):
        if "autonomy" in url:
            return copy.deepcopy(MOCK_AUTONOMY)
        return copy.deepcopy(MOCK_CREDENTIAL)

    return patch("main._post", fake_post), patch("main._get", fake_get)


@pytest.fixture
def client():
    sys.path.insert(0, SERVICE_DIR)
    sys.modules.pop("main", None)
    from main import app
    return TestClient(app)


# ── Health ────────────────────────────────────────────────────────────────────

def test_healthz(client):
    assert client.get("/healthz").status_code == 200


def test_readyz_upstream_ok(client):
    class DummyResponse:
        status_code = 200

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url):
            return DummyResponse()

    with patch("main.httpx.AsyncClient", return_value=DummyClient()):
        r = client.get("/readyz")
    assert r.status_code == 200


# ── Crear agente ──────────────────────────────────────────────────────────────

def test_create_agent_ok(client):
    p, g = _mock_upstream()
    with p, g:
        r = client.post("/v1/agents/create", json=AGENT_SPEC)
    assert r.status_code == 201
    data = r.json()
    assert data["agent_id"] == "agent-abc123"
    assert data["autonomy_level"] == "A0"
    assert data["status"] == "READY"
    assert "bootstrap_code" in data
    assert "bootstrap_config" in data
    assert "agent-abc123" in data["bootstrap_code"]
    assert data["bootstrap_config"]["agent_id"] == "agent-abc123"
    assert data["security_profile"]["token_mode"] == "brokered_ephemeral"
    assert data["credential"]["security_profile"]["enforce_broker_for_tools"] is True


def test_create_agent_bootstrap_contains_gateway(client):
    p, g = _mock_upstream()
    with p, g:
        data = client.post("/v1/agents/create", json=AGENT_SPEC).json()
    assert "gateway_url" in data["bootstrap_code"] or "gateway" in data["bootstrap_code"].lower()
    assert "credential_broker_url" in data["bootstrap_code"]


def test_create_agent_bootstrap_uses_safe_literals(client):
    async def fake_post(url, data):
        if url.endswith("/v1/autonomy/register"):
            return copy.deepcopy(MOCK_AUTONOMY)
        credential = copy.deepcopy(MOCK_CREDENTIAL)
        credential["name"] = data["name"]
        return credential

    async def fake_get(url):
        return copy.deepcopy(MOCK_AUTONOMY)

    malicious = "AgenteMalicioso'; import os; os.system('x') #"
    with patch("main._post", fake_post), patch("main._get", fake_get):
        data = client.post("/v1/agents/create", json={**AGENT_SPEC, "name": malicious}).json()
    assert data["bootstrap_config"]["credential"]["name"].startswith("AgenteMalicioso")
    compile(data["bootstrap_code"], "<bootstrap>", "exec")


def test_create_agent_allows_security_profile_override(client):
    p, g = _mock_upstream()
    spec = dict(AGENT_SPEC)
    spec["security_profile"] = {
        "tool_token_ttl_seconds": 45,
        "allowed_audiences": ["consultar_datos", "crear_acto"],
    }
    with p, g:
        data = client.post("/v1/agents/create", json=spec).json()
    assert data["security_profile"]["tool_token_ttl_seconds"] == 45
    assert data["security_profile"]["allowed_audiences"] == ["consultar_datos", "crear_acto"]


def test_create_agent_aim_failure(client):
    async def failing_post(url, data):
        from fastapi import HTTPException
        raise HTTPException(502, "AIM no disponible")

    with patch("main._post", failing_post):
        r = client.post("/v1/agents/create", json=AGENT_SPEC)
    assert r.status_code == 502


# ── Listar agentes ────────────────────────────────────────────────────────────

def test_list_agents_empty(client):
    async def fake_get(url):
        return []

    with patch("main._get", fake_get):
        r = client.get("/v1/agents")
    assert r.status_code == 200


# ── Evaluar acción ────────────────────────────────────────────────────────────

def test_evaluate_action_allow(client):
    async def fake_get(url):
        return MOCK_CREDENTIAL

    async def fake_post(url, data):
        return {"allow": True, "reasons": [], "obligations": [], "evidence_id": "ev-001", "error": None}

    with patch("main._get", fake_get), patch("main._post", fake_post):
        r = client.post("/v1/agents/agent-abc123/evaluate", json={
            "action": "toolCall",
            "resource": "consultar_datos",
        })
    assert r.status_code == 200
    assert r.json()["decision"]["allow"] is True


def test_evaluate_action_deny(client):
    async def fake_get(url):
        return MOCK_CREDENTIAL

    async def fake_post(url, data):
        return {"allow": False, "reasons": ["POLICY_DENY"], "obligations": [], "evidence_id": "ev-002", "error": None}

    with patch("main._get", fake_get), patch("main._post", fake_post):
        r = client.post("/v1/agents/agent-abc123/evaluate", json={
            "action": "delete",
            "resource": "tabla-critica",
        })
    assert r.status_code == 200
    assert r.json()["decision"]["allow"] is False


# ── Promoción ─────────────────────────────────────────────────────────────────

def test_promote_agent_ok(client):
    async def fake_get(url):
        return MOCK_CREDENTIAL

    async def fake_post(url, data):
        if "promote" in url:
            return {"promoted": True, "new_level": "A1", "failed_gates": []}
        if "autonomy" in url:
            return {"autonomy_level": "A1"}
        return {}

    with patch("main._get", fake_get), patch("main._post", fake_post):
        r = client.post("/v1/agents/agent-abc123/promote", json={
            "target_level": "A1",
            "gates": {k: True for k in ["G1_performance","G2_security","G3_business","G4_history","G5_governance"]},
            "justification": "30 días limpio",
        })
    assert r.status_code == 200
    assert r.json()["promoted"] is True


# ── Dar de baja ───────────────────────────────────────────────────────────────

def test_decommission_agent(client):
    async def fake_get(url):
        return MOCK_CREDENTIAL

    async def fake_post(url, data):
        return {"lifecycle_state": "RETIRED"}

    with patch("main._get", fake_get), patch("main._post", fake_post):
        r = client.delete("/v1/agents/agent-abc123")
    assert r.status_code == 200
    assert r.json()["status"] == "DECOMMISSIONED"

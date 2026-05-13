"""Tests unitarios del AIM Service."""
import os
import sys
import pytest
from fastapi.testclient import TestClient

# Apunta la DB a un archivo temporal en memoria
os.environ["AIM_DB_PATH"] = ":memory:"
os.environ["AIM_HMAC_SECRET"] = "test-secret-aim"

SERVICE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, SERVICE_DIR)
sys.modules.pop("main", None)
from main import app, init_db

@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    """Re-inicializa la DB en memoria antes de cada test."""
    os.environ["AIM_DB_PATH"] = str(tmp_path / "aim.db")
    init_db()
    yield

@pytest.fixture
def client():
    return TestClient(app)


# ── Health ────────────────────────────────────────────────────────────────────

def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_readyz(client):
    r = client.get("/readyz")
    assert r.status_code == 200


# ── Registro de agente ────────────────────────────────────────────────────────

def test_register_agent_ok(client):
    r = client.post("/v1/agents/register", json={
        "name": "AgenteTest",
        "department_id": "dept-test",
        "supervisor_id": "sup-001",
    })
    assert r.status_code == 201
    data = r.json()
    assert data["agent_id"].startswith("agent-")
    assert data["autonomy_level"] == "A0"
    assert data["lifecycle_state"] == "ACTIVE"
    assert "parent_chain_hmac" in data
    assert data["permitted_operations"] == ["modelInvoke", "toolCall"]


def test_register_agent_with_tools(client):
    r = client.post("/v1/agents/register", json={
        "name": "AgenteConTools",
        "department_id": "dept-ops",
        "supervisor_id": "sup-002",
        "permitted_tools": ["consultar_db", "generar_reporte"],
        "rotation_days": 30,
    })
    assert r.status_code == 201
    data = r.json()
    assert "consultar_db" in data["permitted_tools"]
    assert data["rotation_policy"] == "30d"


def test_register_duplicate_name_allowed(client):
    """El sistema admite múltiples agentes con el mismo nombre (IDs distintos)."""
    for _ in range(2):
        r = client.post("/v1/agents/register", json={
            "name": "AgenteRepetido",
            "department_id": "dept-x",
            "supervisor_id": "sup-001",
        })
        assert r.status_code == 201


# ── Obtener credencial ────────────────────────────────────────────────────────

def test_get_credential_ok(client):
    reg = client.post("/v1/agents/register", json={
        "name": "AgenteCred",
        "department_id": "dept-fin",
        "supervisor_id": "sup-001",
    }).json()

    r = client.get(f"/v1/credentials/{reg['agent_id']}")
    assert r.status_code == 200
    assert r.json()["agent_id"] == reg["agent_id"]


def test_get_credential_not_found(client):
    r = client.get("/v1/credentials/agent-no-existe")
    assert r.status_code == 404


# ── Listar agentes ────────────────────────────────────────────────────────────

def test_list_agents_empty(client):
    r = client.get("/v1/agents")
    assert r.status_code == 200
    assert r.json() == []


def test_list_agents_with_data(client):
    for i in range(3):
        client.post("/v1/agents/register", json={
            "name": f"Agente{i}",
            "department_id": "dept-x",
            "supervisor_id": "sup-001",
        })
    r = client.get("/v1/agents")
    assert r.status_code == 200
    assert len(r.json()) == 3


# ── Rotación de credencial ────────────────────────────────────────────────────

def test_rotate_credential_ok(client):
    agent_id = client.post("/v1/agents/register", json={
        "name": "AgenteRotar",
        "department_id": "dept-x",
        "supervisor_id": "sup-001",
    }).json()["agent_id"]

    r = client.post(f"/v1/credentials/{agent_id}/rotate")
    assert r.status_code == 200
    assert r.json()["lifecycle_state"] == "ACTIVE"


def test_rotate_credential_not_found(client):
    r = client.post("/v1/credentials/agent-inexistente/rotate")
    assert r.status_code == 404


# ── Revocación ────────────────────────────────────────────────────────────────

def test_revoke_credential_ok(client):
    agent_id = client.post("/v1/agents/register", json={
        "name": "AgenteRevocar",
        "department_id": "dept-x",
        "supervisor_id": "sup-001",
    }).json()["agent_id"]

    r = client.post(f"/v1/credentials/{agent_id}/revoke",
                    json={"reason": "Agente comprometido"})
    assert r.status_code == 200
    assert r.json()["lifecycle_state"] == "SUSPENDED"


# ── Actualizar autonomía ──────────────────────────────────────────────────────

def test_update_autonomy_ok(client):
    agent_id = client.post("/v1/agents/register", json={
        "name": "AgenteAuto",
        "department_id": "dept-x",
        "supervisor_id": "sup-001",
    }).json()["agent_id"]

    r = client.post(f"/v1/credentials/{agent_id}/autonomy",
                    json={"autonomy_level": "A1", "reason": "30 días limpio"})
    assert r.status_code == 200
    assert r.json()["autonomy_level"] == "A1"


def test_update_autonomy_invalid_level(client):
    agent_id = client.post("/v1/agents/register", json={
        "name": "AgenteAuto2",
        "department_id": "dept-x",
        "supervisor_id": "sup-001",
    }).json()["agent_id"]

    r = client.post(f"/v1/credentials/{agent_id}/autonomy",
                    json={"autonomy_level": "A9"})
    assert r.status_code == 400


# ── Historial ─────────────────────────────────────────────────────────────────

def test_autonomy_history_ok(client):
    agent_id = client.post("/v1/agents/register", json={
        "name": "AgenteHistorial",
        "department_id": "dept-x",
        "supervisor_id": "sup-001",
    }).json()["agent_id"]

    client.post(f"/v1/credentials/{agent_id}/autonomy",
                json={"autonomy_level": "A1", "reason": "Prueba"})

    r = client.get(f"/v1/credentials/{agent_id}/history")
    assert r.status_code == 200
    assert len(r.json()) >= 1

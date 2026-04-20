"""Tests unitarios del HIC Service."""
import os
import sys
import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    os.environ["HIC_DB_PATH"] = str(tmp_path / "hic.db")
    os.environ["HIC_WEBHOOK_URL"] = ""
    from main import init_db
    init_db()
    yield

@pytest.fixture
def client():
    from main import app
    return TestClient(app)


TICKET_BASE = {
    "agent_id": "agent-hic-test",
    "action": "enviar_email",
    "resource": "smtp-externo",
    "reason": "Acción de alto impacto",
    "severity": "HIGH",
    "context": {"destinatario": "cfo@empresa.com"},
    "decision_id": "ev-0000000001",
}


def _create_ticket(client, **overrides):
    payload = {**TICKET_BASE, **overrides}
    return client.post("/v1/tickets", json=payload)


# ── Health ────────────────────────────────────────────────────────────────────

def test_healthz(client):
    assert client.get("/healthz").status_code == 200


# ── Crear ticket ──────────────────────────────────────────────────────────────

def test_create_ticket_ok(client):
    r = _create_ticket(client)
    assert r.status_code == 201
    data = r.json()
    assert data["ticket_id"].startswith("hic-")
    assert data["status"] == "PENDING"
    assert data["severity"] == "HIGH"
    assert "sla_deadline" in data


def test_create_ticket_critical_sla(client):
    r = _create_ticket(client, severity="CRITICAL")
    assert r.status_code == 201
    data = r.json()
    deadline = datetime.fromisoformat(data["sla_deadline"])
    created = datetime.fromisoformat(data["created_at"])
    diff_minutes = (deadline - created).total_seconds() / 60
    assert 4.5 <= diff_minutes <= 5.5  # SLA de 5 minutos


def test_create_ticket_low_sla(client):
    r = _create_ticket(client, severity="LOW")
    data = r.json()
    deadline = datetime.fromisoformat(data["sla_deadline"])
    created = datetime.fromisoformat(data["created_at"])
    diff_hours = (deadline - created).total_seconds() / 3600
    assert 23.5 <= diff_hours <= 24.5  # SLA de 24 horas


# ── Obtener ticket ────────────────────────────────────────────────────────────

def test_get_ticket_ok(client):
    ticket_id = _create_ticket(client).json()["ticket_id"]
    r = client.get(f"/v1/tickets/{ticket_id}")
    assert r.status_code == 200
    assert r.json()["ticket_id"] == ticket_id


def test_get_ticket_not_found(client):
    r = client.get("/v1/tickets/hic-no-existe")
    assert r.status_code == 404


# ── Listar tickets ────────────────────────────────────────────────────────────

def test_list_tickets_empty(client):
    r = client.get("/v1/tickets")
    assert r.status_code == 200
    assert r.json() == []


def test_list_tickets_by_agent(client):
    _create_ticket(client, agent_id="agent-A")
    _create_ticket(client, agent_id="agent-A")
    _create_ticket(client, agent_id="agent-B")

    r = client.get("/v1/tickets?agent_id=agent-A")
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_list_tickets_by_status(client):
    _create_ticket(client)
    _create_ticket(client)
    r = client.get("/v1/tickets?status=PENDING")
    assert len(r.json()) == 2


# ── Aprobar ticket ────────────────────────────────────────────────────────────

def test_approve_ticket(client):
    ticket_id = _create_ticket(client).json()["ticket_id"]
    r = client.post(f"/v1/tickets/{ticket_id}/approve", json={
        "approved": True,
        "reviewer_id": "supervisor-jose",
        "notes": "Revisado y aprobado",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "APPROVED"
    assert data["reviewer_id"] == "supervisor-jose"
    assert data["resolved_at"] is not None


def test_approve_already_resolved(client):
    ticket_id = _create_ticket(client).json()["ticket_id"]
    client.post(f"/v1/tickets/{ticket_id}/approve", json={
        "approved": True, "reviewer_id": "sup-001",
    })
    r = client.post(f"/v1/tickets/{ticket_id}/approve", json={
        "approved": True, "reviewer_id": "sup-002",
    })
    assert r.status_code == 409


# ── Rechazar ticket ───────────────────────────────────────────────────────────

def test_reject_ticket(client):
    ticket_id = _create_ticket(client).json()["ticket_id"]
    r = client.post(f"/v1/tickets/{ticket_id}/reject", json={
        "approved": False,
        "reviewer_id": "supervisor-maria",
        "notes": "No autorizado por política",
    })
    assert r.status_code == 200
    assert r.json()["status"] == "REJECTED"


# ── SLA expirado ──────────────────────────────────────────────────────────────

def test_sla_expired_check(client, tmp_path):
    """Un ticket con SLA vencido debe marcarse como SLA_EXPIRED."""
    import sqlite3
    db_path = os.environ["HIC_DB_PATH"]

    ticket_id = _create_ticket(client, severity="CRITICAL").json()["ticket_id"]

    # Retroceder el SLA artificialmente en la DB
    conn = sqlite3.connect(db_path)
    past = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    conn.execute("UPDATE tickets SET sla_deadline=? WHERE ticket_id=?", (past, ticket_id))
    conn.commit()
    conn.close()

    r = client.get("/v1/tickets/expired/check")
    assert r.status_code == 200
    assert r.json()["expired_count"] >= 1

    ticket = client.get(f"/v1/tickets/{ticket_id}").json()
    assert ticket["status"] == "SLA_EXPIRED"

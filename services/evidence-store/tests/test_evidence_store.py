"""Tests unitarios del Evidence Store."""
import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

@pytest.fixture(autouse=True)
def fresh_ledger(tmp_path):
    """Cada test arranca con un ledger limpio."""
    ledger_path = str(tmp_path / "evidence.jsonl")
    os.environ["LEDGER_PATH"] = ledger_path
    os.environ["EVIDENCE_HMAC_SECRET"] = "test-hmac-secret"

    import main as m
    m._sequence = 0
    m._last_hash = "0" * 64
    m._index = {}
    m._init_ledger()
    yield


@pytest.fixture
def client():
    from main import app
    return TestClient(app)


RECORD_BASE = {
    "subject": "agent-ev-test",
    "action": "toolCall",
    "resource": "consultar_db",
    "context": {"invocationId": "uuid-001"},
    "decision": True,
    "reasons": [],
    "obligations": [],
}


def _append(client, **overrides):
    return client.post("/v1/evidence", json={**RECORD_BASE, **overrides})


# ── Health ────────────────────────────────────────────────────────────────────

def test_healthz(client):
    assert client.get("/healthz").status_code == 200


# ── Head inicial ──────────────────────────────────────────────────────────────

def test_head_empty_ledger(client):
    r = client.get("/v1/head")
    assert r.status_code == 200
    data = r.json()
    assert data["sequence"] == 0
    assert data["entries"] == 0


# ── Agregar evidencia ─────────────────────────────────────────────────────────

def test_append_evidence_ok(client):
    r = _append(client)
    assert r.status_code == 201
    data = r.json()
    assert data["id"].startswith("ev-")
    assert data["sequence_number"] == 1
    assert data["hash"].startswith("sha256:")
    assert "timestamp" in data


def test_append_increments_sequence(client):
    for i in range(5):
        r = _append(client)
        assert r.json()["sequence_number"] == i + 1


def test_append_updates_head(client):
    _append(client)
    _append(client)
    r = client.get("/v1/head")
    assert r.json()["sequence"] == 2
    assert r.json()["entries"] == 2


# ── Obtener por ID ────────────────────────────────────────────────────────────

def test_get_evidence_by_id(client):
    ev_id = _append(client).json()["id"]
    r = client.get(f"/v1/evidence/{ev_id}")
    assert r.status_code == 200
    assert r.json()["id"] == ev_id
    assert r.json()["subject"] == "agent-ev-test"


def test_get_evidence_not_found(client):
    r = client.get("/v1/evidence/ev-9999999999")
    assert r.status_code == 404


# ── Listar evidencias ─────────────────────────────────────────────────────────

def test_list_evidence_empty(client):
    r = client.get("/v1/evidence")
    assert r.status_code == 200
    assert r.json() == []


def test_list_evidence_default_limit(client):
    for _ in range(25):
        _append(client)
    r = client.get("/v1/evidence")
    assert len(r.json()) == 20  # default limit


def test_list_evidence_with_limit(client):
    for _ in range(10):
        _append(client)
    r = client.get("/v1/evidence?limit=5")
    assert len(r.json()) == 5


def test_list_evidence_filter_by_subject(client):
    _append(client, subject="agent-A")
    _append(client, subject="agent-A")
    _append(client, subject="agent-B")
    r = client.get("/v1/evidence?subject=agent-A")
    result = r.json()
    assert all(e["subject"] == "agent-A" for e in result)
    assert len(result) == 2


# ── Integridad de la cadena HMAC ──────────────────────────────────────────────

def test_verify_chain_empty(client):
    r = client.get("/v1/evidence/verify/chain")
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_verify_chain_valid(client):
    for _ in range(10):
        _append(client)
    r = client.get("/v1/evidence/verify/chain")
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is True
    assert data["entries_checked"] == 10


def test_verify_chain_detects_tampering(client, tmp_path):
    """Si un registro del ledger se modifica, la verificación debe fallar."""
    import json

    for _ in range(5):
        _append(client)

    ledger_path = os.environ["LEDGER_PATH"]
    with open(ledger_path, "r") as f:
        lines = f.readlines()

    # Tamperear la tercera entrada
    entry = json.loads(lines[2])
    entry["decision"] = not entry["decision"]
    lines[2] = json.dumps(entry) + "\n"

    with open(ledger_path, "w") as f:
        f.writelines(lines)

    # Recargar el estado global
    import main as m
    m._sequence = 0
    m._last_hash = "0" * 64
    m._index = {}
    m._init_ledger()

    r = client.get("/v1/evidence/verify/chain")
    assert r.json()["valid"] is False


# ── Cadena prev_hash ──────────────────────────────────────────────────────────

def test_chain_links(client):
    """Cada entrada debe referenciar el hash de la anterior."""
    ids = []
    for _ in range(3):
        ids.append(_append(client).json()["id"])

    entries = [client.get(f"/v1/evidence/{eid}").json() for eid in ids]
    assert entries[1]["prev_hash"] == entries[0]["entry_hmac"]
    assert entries[2]["prev_hash"] == entries[1]["entry_hmac"]

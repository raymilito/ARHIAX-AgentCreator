"""Tests unitarios del BBR Service."""
import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    os.environ["BBR_DB_PATH"] = str(tmp_path / "bbr.db")
    from main import init_db
    init_db()
    yield

@pytest.fixture
def client():
    from main import app
    return TestClient(app)


AGENT_ID = "agent-bbr-test"


def _observe(client, duration_ms=250.0, token_count=500, outcome="ALLOW"):
    return client.post(f"/v1/baseline/{AGENT_ID}/observe", json={
        "agent_id": AGENT_ID,
        "operation_type": "toolCall",
        "tool_name": "consultar_db",
        "duration_ms": duration_ms,
        "token_count": token_count,
        "outcome": outcome,
        "tags": ["test"],
    })


def _seed_baseline(client, n=10):
    """Inserta n observaciones para tener línea base válida."""
    for i in range(n):
        _observe(client, duration_ms=200.0 + i * 5, token_count=500 + i * 10)


# ── Health ────────────────────────────────────────────────────────────────────

def test_healthz(client):
    assert client.get("/healthz").status_code == 200


# ── Observaciones ─────────────────────────────────────────────────────────────

def test_observe_ok(client):
    r = _observe(client)
    assert r.status_code == 200
    assert r.json()["status"] == "recorded"


def test_observe_multiple(client):
    for _ in range(5):
        _observe(client)
    r = client.get(f"/v1/baseline/{AGENT_ID}/observations")
    assert r.status_code == 200
    assert len(r.json()) == 5


def test_observations_limit(client):
    for _ in range(10):
        _observe(client)
    r = client.get(f"/v1/baseline/{AGENT_ID}/observations?limit=3")
    assert r.status_code == 200
    assert len(r.json()) == 3


# ── Línea base ────────────────────────────────────────────────────────────────

def test_baseline_no_data(client):
    r = client.get(f"/v1/baseline/{AGENT_ID}")
    assert r.status_code == 200
    data = r.json()
    assert data["has_baseline"] is False
    assert data["sample_count"] == 0


def test_baseline_insufficient_samples(client):
    """Con menos de 5 observaciones, has_baseline debe ser False."""
    for _ in range(4):
        _observe(client)
    r = client.get(f"/v1/baseline/{AGENT_ID}")
    assert r.json()["has_baseline"] is False


def test_baseline_valid_after_5(client):
    _seed_baseline(client, n=5)
    r = client.get(f"/v1/baseline/{AGENT_ID}")
    data = r.json()
    assert data["has_baseline"] is True
    assert data["sample_count"] == 5
    assert data["mean_duration_ms"] > 0


def test_baseline_accumulates(client):
    _seed_baseline(client, n=15)
    r = client.get(f"/v1/baseline/{AGENT_ID}")
    data = r.json()
    assert data["sample_count"] == 15
    assert data["has_baseline"] is True


# ── Score de desviación ───────────────────────────────────────────────────────

def test_score_no_baseline(client):
    """Sin línea base, sigma_deviation debe ser 0.0."""
    r = client.post(f"/v1/baseline/{AGENT_ID}/score", json={
        "duration_ms": 9000.0,
        "token_count": 9999,
    })
    assert r.status_code == 200
    assert r.json()["sigma_deviation"] == 0.0


def test_score_normal_within_baseline(client):
    """Operación dentro del rango normal → sigma bajo."""
    _seed_baseline(client, n=20)
    r = client.post(f"/v1/baseline/{AGENT_ID}/score", json={
        "duration_ms": 225.0,   # cerca de la media
        "token_count": 595,
    })
    assert r.status_code == 200
    assert r.json()["sigma_deviation"] < 2.0


def test_score_extreme_outlier(client):
    """Operación muy fuera del rango normal → sigma alto."""
    _seed_baseline(client, n=20)
    r = client.post(f"/v1/baseline/{AGENT_ID}/score", json={
        "duration_ms": 99999.0,  # extremo
        "token_count": 99999,
    })
    assert r.status_code == 200
    assert r.json()["sigma_deviation"] > 3.0


# ── Agente sin observaciones ──────────────────────────────────────────────────

def test_baseline_unknown_agent(client):
    r = client.get("/v1/baseline/agente-sin-datos")
    assert r.status_code == 200
    assert r.json()["has_baseline"] is False

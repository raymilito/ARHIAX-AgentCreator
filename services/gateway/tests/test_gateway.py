"""Tests unitarios del Gateway (PEP).

El Gateway depende de OPA y Evidence Store (HTTP externos).
Los tests mockean ambos con unittest.mock para no requerir servicios activos.
"""
import os
import sys
import base64
import json
import time
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

os.environ["OPA_URL"] = "http://opa-mock:8181"
os.environ["EVIDENCE_STORE_URL"] = "http://evidence-mock:8090"

SERVICE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, SERVICE_DIR)
sys.modules.pop("main", None)


# Clave ES256 unica para toda la suite — se inyecta como JWKS en el gateway
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_PUBLIC_KEY = _TEST_PRIVATE_KEY.public_key()


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _compute_test_kid() -> str:
    import hashlib as _h
    nums = _TEST_PUBLIC_KEY.public_numbers()
    jwk_min = {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64u(nums.x.to_bytes(32, "big")),
        "y": _b64u(nums.y.to_bytes(32, "big")),
    }
    raw = json.dumps(jwk_min, separators=(",", ":"), sort_keys=True).encode()
    return _h.sha256(raw).hexdigest()[:16]


_TEST_KID = _compute_test_kid()


@pytest.fixture
def client():
    sys.path.insert(0, SERVICE_DIR)
    sys.modules.pop("main", None)
    from main import (
        app, _metrics, _revoked_jtis, _seen_jtis,
        _set_jwks_keys_for_tests, _idem_cache,
        _jti_origins, _subject_recent_denies,
    )
    for key in list(_metrics.keys()):
        _metrics[key] = 0
    _seen_jtis.clear()
    _revoked_jtis.clear()
    _idem_cache.clear()
    _jti_origins.clear()
    _subject_recent_denies.clear()
    _set_jwks_keys_for_tests({_TEST_KID: _TEST_PUBLIC_KEY})
    return TestClient(app)


DECIDE_REQUEST = {
    "subject": "agent-gw-test",
    "action": "toolCall",
    "resource": "consultar_datos",
    "context": {
        "invocationId": "uuid-gw-001",
        "operationType": "toolCall",
        "requestedAutonomyLevel": "A1",
    },
}


def _mock_opa_allow(outcome="ALLOW"):
    return AsyncMock(return_value=(True, [], [{"type": "rate_limit", "value": 100}], outcome))


def _mock_opa_deny(reason="POLICY_DENY", outcome="DENY"):
    return AsyncMock(return_value=(False, [reason], [], outcome))


def _mock_evidence(ev_id="ev-0000000001"):
    return AsyncMock(return_value=ev_id)


def _ephemeral_auth(tool_name="consultar_datos", invocation_id="uuid-gw-001", **binding):
    issued = int(time.time())
    exp = issued + 60
    payload = {
        "iss": "arhiax-credential-broker",
        "sub": "agent-gw-test",
        "act": "agent-gw-test",
        "aud": tool_name,
        "scope": f"tool:execute:{tool_name}",
        "jti": f"jti-{tool_name}-{invocation_id}-{'-'.join(f'{k}:{v}' for k, v in binding.items()) or 'base'}",
        "iat": issued,
        "nbf": issued,
        "exp": exp,
        "cnf": {"kid": "pop-test"},
        "tool_name": tool_name,
        "invocation_id": invocation_id,
        "context_binding": {"tool_name": tool_name, **{k: str(v) for k, v in binding.items()}},
        "requested_autonomy_level": "A1",
    }
    header = {"alg": "ES256", "typ": "JWT", "kid": _TEST_KID}

    def enc(value):
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return _b64u(raw)

    unsigned = f"{enc(header)}.{enc(payload)}"
    der_sig = _TEST_PRIVATE_KEY.sign(unsigned.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    token = f"{unsigned}.{_b64u(raw_sig)}"
    return {"token": token}


# ── Health ────────────────────────────────────────────────────────────────────

def test_healthz(client):
    assert client.get("/healthz").status_code == 200


# ── Decisión: ALLOW ───────────────────────────────────────────────────────────

def test_decide_allow(client):
    with patch("main._query_opa", _mock_opa_allow()), \
         patch("main._append_evidence", _mock_evidence()):
        r = client.post("/v1/decide", json=DECIDE_REQUEST)
    assert r.status_code == 200
    data = r.json()
    assert data["allow"] is True
    assert data["evidence_id"] == "ev-0000000001"
    assert data["error"] is None


def test_decide_propagates_outcome(client):
    with patch("main._query_opa", _mock_opa_allow(outcome="ALLOW_WITH_HIC_NOTIFICATION")), \
         patch("main._append_evidence", _mock_evidence()):
        r = client.post("/v1/decide", json=DECIDE_REQUEST)
    assert r.json()["outcome"] == "ALLOW_WITH_HIC_NOTIFICATION"


def test_decide_escalate_to_human(client):
    with patch("main._query_opa", _mock_opa_deny("STEP_UP_REQUIRED", outcome="ESCALATE_TO_HUMAN")), \
         patch("main._append_evidence", _mock_evidence()):
        r = client.post("/v1/decide", json=DECIDE_REQUEST)
    assert r.json()["outcome"] == "ESCALATE_TO_HUMAN"
    assert r.json()["allow"] is False


def test_decide_allow_increments_metric(client):
    with patch("main._query_opa", _mock_opa_allow()), \
         patch("main._append_evidence", _mock_evidence()):
        client.post("/v1/decide", json=DECIDE_REQUEST)
    from main import _metrics
    assert _metrics["decide_allow"] == 1


# ── Decisión: DENY ────────────────────────────────────────────────────────────

def test_decide_deny(client):
    with patch("main._query_opa", _mock_opa_deny("POLICY_DENY")), \
         patch("main._append_evidence", _mock_evidence()):
        r = client.post("/v1/decide", json=DECIDE_REQUEST)
    assert r.status_code == 200
    data = r.json()
    assert data["allow"] is False
    assert "POLICY_DENY" in data["reasons"]


# ── Detección de inyección ────────────────────────────────────────────────────

@pytest.mark.parametrize("injection", [
    "ignore previous instructions",
    "UNION SELECT * FROM",
    "<script>alert(1)</script>",
    "'; DROP TABLE agents; --",
    "javascript:void(0)",
    "${7*7}",
])
def test_injection_detected(client, injection):
    payload = {**DECIDE_REQUEST, "context": {"input": {"query": injection}}}
    with patch("main._append_evidence", _mock_evidence()):
        r = client.post("/v1/decide", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["allow"] is False
    assert any("INJECTION" in reason for reason in data["reasons"])


# ── Body demasiado grande ─────────────────────────────────────────────────────

def test_body_too_large(client):
    large_context = {"data": "x" * (2 * 1024 * 1024)}  # 2 MiB
    r = client.post("/v1/decide", json={**DECIDE_REQUEST, "context": large_context})
    assert r.status_code == 413


# ── OPA no disponible → fail-closed ──────────────────────────────────────────

def test_opa_unavailable_fail_closed(client):
    from fastapi import HTTPException

    async def opa_fail(*args, **kwargs):
        raise HTTPException(503, "OPA no disponible")

    with patch("main._query_opa", opa_fail):
        r = client.post("/v1/decide", json=DECIDE_REQUEST)
    assert r.status_code == 503


# ── Evidence Store falla → decisión se retorna igual (fail-open) ──────────────

def test_evidence_store_failure_fail_open(client):
    async def evidence_fail(*args, **kwargs):
        raise Exception("Evidence Store caído")

    with patch("main._query_opa", _mock_opa_allow()), \
         patch("main._append_evidence", evidence_fail):
        r = client.post("/v1/decide", json=DECIDE_REQUEST)
    assert r.status_code == 200
    data = r.json()
    assert data["allow"] is True
    assert data["evidence_id"] == ""  # vacío porque falló


# ── Métricas Prometheus ───────────────────────────────────────────────────────

def test_metrics_endpoint(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    text = r.text
    assert "arhiax_gateway_decide_total" in text
    assert "arhiax_gateway_opa_errors_total" in text


# ── Tipos de acción válidos ───────────────────────────────────────────────────

@pytest.mark.parametrize("action", ["toolCall", "modelInvoke", "dataAccess", "interAgentCall"])
def test_valid_action_types(client, action):
    req = {**DECIDE_REQUEST, "action": action}
    with patch("main._query_opa", _mock_opa_allow()), \
         patch("main._append_evidence", _mock_evidence()):
        r = client.post("/v1/decide", json=req)
    assert r.status_code == 200


def test_ephemeral_auth_validates_audience_and_invocation(client):
    req = {
        **DECIDE_REQUEST,
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "ephemeralAuth": _ephemeral_auth(),
        },
    }
    with patch("main._query_opa", _mock_opa_allow()), \
         patch("main._append_evidence", _mock_evidence()):
        r = client.post("/v1/decide", json=req)
    assert r.status_code == 200
    assert r.json()["allow"] is True


def test_ephemeral_auth_rejects_audience_mismatch(client):
    req = {
        **DECIDE_REQUEST,
        "resource": "otro_recurso",
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "ephemeralAuth": _ephemeral_auth(),
        },
    }
    with patch("main._query_opa", _mock_opa_allow()):
        r = client.post("/v1/decide", json=req)
    assert r.status_code == 403


def test_ephemeral_auth_rejects_context_binding_mismatch(client):
    req = {
        **DECIDE_REQUEST,
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "case_id": "case-2",
            "ephemeralAuth": _ephemeral_auth(case_id="case-1"),
        },
    }
    with patch("main._query_opa", _mock_opa_allow()):
        r = client.post("/v1/decide", json=req)
    assert r.status_code == 403


def test_ephemeral_auth_rejects_revoked_jti(client):
    auth = _ephemeral_auth()
    import json as _json
    payload_b64 = auth["token"].split(".")[1]
    pad = "=" * (-len(payload_b64) % 4)
    jti = _json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode())["jti"]
    rev = client.post(f"/v1/ephemeral/revoke/{jti}")
    assert rev.status_code == 200
    req = {
        **DECIDE_REQUEST,
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "ephemeralAuth": auth,
        },
    }
    with patch("main._query_opa", _mock_opa_allow()):
        r = client.post("/v1/decide", json=req)
    assert r.status_code == 401
    from main import _metrics
    assert _metrics["revoked_blocked"] >= 1


def test_mtls_kwargs_includes_cert_when_env_set(monkeypatch):
    monkeypatch.setattr("main._CLIENT_CERT", "/certs/gateway.crt")
    monkeypatch.setattr("main._CLIENT_KEY", "/certs/gateway.key")
    monkeypatch.setattr("main._CA_CERT", "/certs/ca.crt")
    from main import _mtls_kwargs
    kwargs = _mtls_kwargs()
    assert kwargs["verify"] == "/certs/ca.crt"
    assert kwargs["cert"] == ("/certs/gateway.crt", "/certs/gateway.key")


def test_mtls_kwargs_omits_cert_when_unset(monkeypatch):
    monkeypatch.setattr("main._CLIENT_CERT", None)
    monkeypatch.setattr("main._CLIENT_KEY", None)
    from main import _mtls_kwargs
    kwargs = _mtls_kwargs()
    assert "cert" not in kwargs


def test_metrics_exposes_jti_store_backend(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert 'arhiax_gateway_jti_store_backend{backend="memory"}' in r.text


def _dpop_auth_pair(tool_name="consultar_datos", invocation_id="uuid-gw-001"):
    """Genera un token con cnf.jkt y su DPoP-proof emparejado."""
    client_key = ec.generate_private_key(ec.SECP256R1())
    cnums = client_key.public_key().public_numbers()
    cjwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u(cnums.x.to_bytes(32, "big")),
        "y": _b64u(cnums.y.to_bytes(32, "big")),
    }
    canonical = json.dumps(cjwk, separators=(",", ":"), sort_keys=True).encode()
    import hashlib as _h
    jkt = _b64u(_h.sha256(canonical).digest())

    issued = int(time.time())
    payload = {
        "iss": "arhiax-credential-broker",
        "sub": "agent-gw-test",
        "act": "agent-gw-test",
        "aud": tool_name,
        "scope": f"tool:execute:{tool_name}",
        "jti": f"jti-dpop-{invocation_id}",
        "iat": issued,
        "nbf": issued,
        "exp": issued + 60,
        "cnf": {"kid": "pop", "jkt": jkt},
        "tool_name": tool_name,
        "invocation_id": invocation_id,
        "context_binding": {"tool_name": tool_name},
        "requested_autonomy_level": "A1",
    }
    header = {"alg": "ES256", "typ": "JWT", "kid": _TEST_KID}

    def enc(value):
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return _b64u(raw)

    unsigned = f"{enc(header)}.{enc(payload)}"
    der_sig = _TEST_PRIVATE_KEY.sign(unsigned.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    token = f"{unsigned}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    # DPoP proof
    proof_header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": cjwk}
    from main import DPOP_HTU
    proof_payload = {"htm": "POST", "htu": DPOP_HTU, "iat": issued, "jti": f"dpop-{invocation_id}"}
    ph = enc(proof_header)
    pp = enc(proof_payload)
    pder = client_key.sign(f"{ph}.{pp}".encode(), ec.ECDSA(hashes.SHA256()))
    pr, ps = decode_dss_signature(pder)
    proof = f"{ph}.{pp}.{_b64u(pr.to_bytes(32, 'big') + ps.to_bytes(32, 'big'))}"
    return {"token": token, "dpop": proof}, client_key


def test_anomaly_aud_mismatch_increments_counter(client):
    auth = _ephemeral_auth(tool_name="tool_a")
    req = {
        **DECIDE_REQUEST,
        "resource": "tool_b",  # mismatch
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "tool_a",
            "ephemeralAuth": auth,
        },
    }
    with patch("main._query_opa", _mock_opa_allow()):
        client.post("/v1/decide", json=req)
    from main import _metrics
    assert _metrics["anomaly_aud_mismatch"] == 1


def test_anomaly_dpop_failure_counted_when_proof_missing(client):
    auth, _ = _dpop_auth_pair()
    auth.pop("dpop", None)
    req = {
        **DECIDE_REQUEST,
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "ephemeralAuth": auth,
        },
    }
    with patch("main._query_opa", _mock_opa_allow()):
        client.post("/v1/decide", json=req)
    from main import _metrics
    assert _metrics["anomaly_dpop_failure"] >= 1


def test_anomaly_burst_denials_tracked_per_subject(client, monkeypatch):
    monkeypatch.setattr("main.BURST_DENY_THRESHOLD", 3)
    opa_deny = AsyncMock(return_value=(False, ["POLICY_DENY"], [], "DENY"))
    with patch("main._query_opa", opa_deny), \
         patch("main._append_evidence", _mock_evidence()):
        for _ in range(3):
            client.post("/v1/decide", json=DECIDE_REQUEST)
    from main import _metrics, _subject_recent_denies
    assert _metrics["anomaly_burst_denials"] >= 1
    assert "agent-gw-test" in _subject_recent_denies


def test_anomalies_endpoint_returns_snapshot(client):
    r = client.get("/v1/anomalies")
    assert r.status_code == 200
    body = r.json()
    assert "counters" in body and "shared_jtis" in body and "burst_subjects" in body


def test_idempotency_key_returns_cached_response(client):
    headers = {"Idempotency-Key": "uuid-idem-1"}
    opa_mock = AsyncMock(return_value=(True, [], [], "ALLOW"))
    ev_mock = AsyncMock(return_value="ev-77")
    with patch("main._query_opa", opa_mock), \
         patch("main._append_evidence", ev_mock):
        r1 = client.post("/v1/decide", json=DECIDE_REQUEST, headers=headers)
        r2 = client.post("/v1/decide", json=DECIDE_REQUEST, headers=headers)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json()
    # OPA y evidence se invocaron solo una vez
    assert opa_mock.await_count == 1
    assert ev_mock.await_count == 1
    from main import _metrics
    assert _metrics["idempotent_hits"] == 1


def test_idempotency_skipped_when_ephemeral_auth_present(client):
    headers = {"Idempotency-Key": "uuid-idem-2"}
    req = {
        **DECIDE_REQUEST,
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "ephemeralAuth": _ephemeral_auth(),
        },
    }
    opa_mock = AsyncMock(return_value=(True, [], [], "ALLOW"))
    with patch("main._query_opa", opa_mock), \
         patch("main._append_evidence", _mock_evidence()):
        client.post("/v1/decide", json=req, headers=headers)
    # No se debio cachear (no contamos hit en metricas)
    from main import _metrics
    assert _metrics["idempotent_hits"] == 0


def test_dpop_proof_accepted_for_jkt_bound_token(client):
    auth, _ = _dpop_auth_pair()
    req = {
        **DECIDE_REQUEST,
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "ephemeralAuth": auth,
        },
    }
    with patch("main._query_opa", _mock_opa_allow()), \
         patch("main._append_evidence", _mock_evidence()):
        r = client.post("/v1/decide", json=req)
    assert r.status_code == 200
    assert r.json()["allow"] is True


def test_dpop_proof_missing_rejects_jkt_bound_token(client):
    auth, _ = _dpop_auth_pair()
    auth.pop("dpop", None)
    req = {
        **DECIDE_REQUEST,
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "ephemeralAuth": auth,
        },
    }
    with patch("main._query_opa", _mock_opa_allow()):
        r = client.post("/v1/decide", json=req)
    assert r.status_code == 401


def test_dpop_proof_wrong_key_rejected(client):
    auth, _ = _dpop_auth_pair()
    # Reemplaza el proof por uno firmado con otra clave
    other = ec.generate_private_key(ec.SECP256R1())
    onums = other.public_key().public_numbers()
    ojwk = {
        "kty": "EC", "crv": "P-256",
        "x": _b64u(onums.x.to_bytes(32, "big")),
        "y": _b64u(onums.y.to_bytes(32, "big")),
    }
    from main import DPOP_HTU
    issued = int(time.time())
    ph = _b64u(json.dumps({"typ": "dpop+jwt", "alg": "ES256", "jwk": ojwk}, separators=(",", ":"), sort_keys=True).encode())
    pp = _b64u(json.dumps({"htm": "POST", "htu": DPOP_HTU, "iat": issued, "jti": "x"}, separators=(",", ":"), sort_keys=True).encode())
    pder = other.sign(f"{ph}.{pp}".encode(), ec.ECDSA(hashes.SHA256()))
    pr, ps = decode_dss_signature(pder)
    auth["dpop"] = f"{ph}.{pp}.{_b64u(pr.to_bytes(32, 'big') + ps.to_bytes(32, 'big'))}"
    req = {
        **DECIDE_REQUEST,
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "ephemeralAuth": auth,
        },
    }
    with patch("main._query_opa", _mock_opa_allow()):
        r = client.post("/v1/decide", json=req)
    assert r.status_code == 401


def test_ephemeral_auth_detects_replay(client):
    auth = _ephemeral_auth()
    req = {
        **DECIDE_REQUEST,
        "context": {
            **DECIDE_REQUEST["context"],
            "toolName": "consultar_datos",
            "ephemeralAuth": auth,
        },
    }
    with patch("main._query_opa", _mock_opa_allow()), \
         patch("main._append_evidence", _mock_evidence()):
        first = client.post("/v1/decide", json=req)
        second = client.post("/v1/decide", json=req)
    assert first.status_code == 200
    assert second.status_code == 409

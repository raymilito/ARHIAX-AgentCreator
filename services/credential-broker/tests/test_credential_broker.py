"""Unit tests for the ARHIAX Credential Broker."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ["BROKER_PERSIST_KEY"] = "false"
os.environ["AIM_URL"] = "http://aim-mock:8200"

SERVICE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, SERVICE_DIR)
sys.modules.pop("main", None)


PARENT_HMAC = "parent-hmac-secret"
BASE_CREDENTIAL = {
    "agent_id": "agent-broker-test",
    "lifecycle_state": "ACTIVE",
    "parent_chain_hmac": PARENT_HMAC,
    "permitted_operations": ["toolCall", "interAgentCall"],
    "permitted_tools": ["consultar_datos"],
}


@pytest.fixture
def client():
    sys.path.insert(0, SERVICE_DIR)
    sys.modules.pop("main", None)
    import main

    main.REQUIRE_SIGNED_AGENT_PROOF = False
    main._proof_nonces.clear()
    return TestClient(main.app)


def _request(**overrides):
    payload = {
        "agent_id": "agent-broker-test",
        "tool_name": "consultar_datos",
        "audience": "consultar_datos",
        "scope": "tool:execute:consultar_datos",
        "invocation_id": "inv-001",
        "context_binding": {"tool_name": "consultar_datos", "case_id": "CASE-1"},
        "ttl_seconds": 999,
        "requested_autonomy_level": "A1",
    }
    payload.update(overrides)
    return payload


def _proof(payload, *, nonce="nonce-1", issued_at=None, secret=PARENT_HMAC):
    issued = str(issued_at if issued_at is not None else int(time.time()))
    binding = json.dumps(payload["context_binding"], separators=(",", ":"), sort_keys=True)
    message = "|".join([
        payload["agent_id"],
        payload["tool_name"],
        payload["audience"],
        payload["scope"],
        payload["invocation_id"],
        str(payload["ttl_seconds"]),
        payload["requested_autonomy_level"],
        binding,
        nonce,
        issued,
    ])
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return {"nonce": nonce, "issued_at": issued, "signature": signature}


def _payload_segment(token):
    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode())


def test_healthz_and_jwks(client):
    assert client.get("/healthz").status_code == 200
    jwks = client.get("/.well-known/jwks.json")
    assert jwks.status_code == 200
    key = jwks.json()["keys"][0]
    assert key["alg"] == "ES256"
    assert key["kid"]


def test_issue_tool_token_accepts_signed_agent_proof(client):
    payload = _request()
    payload["agent_credential_proof"] = _proof(payload)
    with patch("main._load_agent_credential", AsyncMock(return_value=BASE_CREDENTIAL)):
        response = client.post("/v1/tokens/tool", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "DPoP"
    assert body["jti"].startswith("jti-")
    claims = _payload_segment(body["token"])
    assert claims["aud"] == "consultar_datos"
    assert claims["scope"] == "tool:execute:consultar_datos"
    assert claims["exp"] - claims["iat"] == 300


def test_issue_tool_token_rejects_scope_audience_mismatch(client):
    payload = _request(audience="otra_herramienta")
    payload["agent_credential_proof"] = _proof(payload)
    with patch("main._load_agent_credential", AsyncMock(return_value=BASE_CREDENTIAL)):
        response = client.post("/v1/tokens/tool", json=payload)
    assert response.status_code == 403


def test_requires_signed_proof_when_configured(client):
    import main

    main.REQUIRE_SIGNED_AGENT_PROOF = True
    payload = _request(agent_credential_hmac=PARENT_HMAC)
    with patch("main._load_agent_credential", AsyncMock(return_value=BASE_CREDENTIAL)):
        response = client.post("/v1/tokens/tool", json=payload)
    assert response.status_code == 401


def test_legacy_hmac_still_supported_when_not_required(client):
    payload = _request(agent_credential_hmac=PARENT_HMAC)
    with patch("main._load_agent_credential", AsyncMock(return_value=BASE_CREDENTIAL)):
        response = client.post("/v1/tokens/tool", json=payload)
    assert response.status_code == 200


def test_signed_proof_rejects_replay_nonce(client):
    payload = _request()
    payload["agent_credential_proof"] = _proof(payload, nonce="same-nonce")
    with patch("main._load_agent_credential", AsyncMock(return_value=BASE_CREDENTIAL)):
        first = client.post("/v1/tokens/tool", json=payload)
        second = client.post("/v1/tokens/tool", json=payload)
    assert first.status_code == 200
    assert second.status_code == 409


def test_signed_proof_rejects_bad_signature(client):
    payload = _request()
    payload["agent_credential_proof"] = _proof(payload, secret="wrong")
    with patch("main._load_agent_credential", AsyncMock(return_value=BASE_CREDENTIAL)):
        response = client.post("/v1/tokens/tool", json=payload)
    assert response.status_code == 401

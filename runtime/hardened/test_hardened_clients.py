"""
ARHIAX v11.4 — Hardened Clients Test Suite
===========================================

Unit tests covering:
  - HardenedClient base: retry, circuit breaker state transitions, metrics
  - Each of the 6 concrete clients: contract parity with InMemory counterparts
  - Fail-closed semantics on upstream failures
  - ATK-C07 attestation without leaking secrets

Run:
    pip install pytest pytest-asyncio respx httpx tenacity prometheus-client
    pytest test_hardened_clients.py -v

Note: all tests use respx to mock httpx calls — no real network required.
"""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest
import respx

from hardened_base import (
    CircuitOpenError,
    CircuitState,
    ClientConfig,
    HardenedClient,
    UpstreamContractError,
    UpstreamUnavailableError,
)
from hardened_clients import (
    HardenedAIMClient,
    HardenedAUTClient,
    HardenedBBRClient,
    HardenedEGAClient,
    HardenedHICClient,
    HardenedOPAClient,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _cfg(name: str = "test", **overrides) -> ClientConfig:
    return ClientConfig(
        name=name,
        base_url="https://upstream.test",
        auth_token="secret-token",
        timeout_seconds=1.0,
        connect_timeout_seconds=0.5,
        max_retries=3,
        retry_min_wait=0.01,
        retry_max_wait=0.05,
        circuit_failure_threshold=3,
        circuit_reset_seconds=0.1,
        **overrides,
    )


@pytest.fixture
async def base_client():
    client = HardenedClient(_cfg())
    yield client
    await client.close()


# ---------------------------------------------------------------------------
# HardenedClient base behavior
# ---------------------------------------------------------------------------


class TestHardenedBase:
    async def test_success_returns_parsed_json(self, base_client):
        with respx.mock(base_url="https://upstream.test") as mock:
            mock.get("/v1/echo").mock(return_value=httpx.Response(200, json={"ok": True}))
            result = await base_client._request("GET", "/v1/echo")
            assert result == {"ok": True}

    async def test_auth_header_injected(self, base_client):
        with respx.mock(base_url="https://upstream.test") as mock:
            route = mock.get("/v1/echo").mock(return_value=httpx.Response(200, json={}))
            await base_client._request("GET", "/v1/echo")
            request = route.calls.last.request
            assert request.headers["authorization"] == "Bearer secret-token"
            assert request.headers["user-agent"].startswith("arhiax-atk/")

    async def test_correlation_id_forwarded(self, base_client):
        with respx.mock(base_url="https://upstream.test") as mock:
            route = mock.get("/v1/echo").mock(return_value=httpx.Response(200, json={}))
            await base_client._request("GET", "/v1/echo", correlation_id="env-abc123")
            assert route.calls.last.request.headers["x-arhiax-correlation-id"] == "env-abc123"

    async def test_retry_on_5xx_then_success(self, base_client):
        with respx.mock(base_url="https://upstream.test") as mock:
            mock.get("/v1/flaky").mock(
                side_effect=[
                    httpx.Response(503),
                    httpx.Response(503),
                    httpx.Response(200, json={"recovered": True}),
                ]
            )
            result = await base_client._request("GET", "/v1/flaky")
            assert result == {"recovered": True}

    async def test_retry_exhausted_raises_unavailable(self, base_client):
        with respx.mock(base_url="https://upstream.test") as mock:
            mock.get("/v1/down").mock(return_value=httpx.Response(503))
            with pytest.raises(UpstreamUnavailableError):
                await base_client._request("GET", "/v1/down")

    async def test_4xx_raises_contract_error_no_retry(self, base_client):
        with respx.mock(base_url="https://upstream.test") as mock:
            route = mock.get("/v1/bad").mock(return_value=httpx.Response(400, text="bad input"))
            with pytest.raises(UpstreamContractError):
                await base_client._request("GET", "/v1/bad")
            # 4xx must NOT be retried
            assert route.call_count == 1

    async def test_4xx_does_not_trip_breaker(self, base_client):
        with respx.mock(base_url="https://upstream.test") as mock:
            mock.get("/v1/bad").mock(return_value=httpx.Response(400))
            for _ in range(5):
                with pytest.raises(UpstreamContractError):
                    await base_client._request("GET", "/v1/bad")
            assert base_client.breaker.state == CircuitState.CLOSED

    async def test_circuit_opens_after_threshold(self, base_client):
        with respx.mock(base_url="https://upstream.test") as mock:
            mock.get("/v1/dead").mock(return_value=httpx.Response(503))
            # threshold = 3
            for _ in range(3):
                with pytest.raises(UpstreamUnavailableError):
                    await base_client._request("GET", "/v1/dead")
            assert base_client.breaker.state == CircuitState.OPEN

            # next call should short-circuit immediately
            with pytest.raises(CircuitOpenError):
                await base_client._request("GET", "/v1/dead")

    async def test_circuit_half_open_recovers_on_success(self, base_client):
        with respx.mock(base_url="https://upstream.test") as mock:
            mock.get("/v1/recovery").mock(return_value=httpx.Response(503))
            for _ in range(3):
                with pytest.raises(UpstreamUnavailableError):
                    await base_client._request("GET", "/v1/recovery")
            assert base_client.breaker.state == CircuitState.OPEN

            # wait for reset timeout
            await asyncio.sleep(0.15)

            # next call transitions to HALF_OPEN, and if it succeeds → CLOSED
            mock.get("/v1/recovery").mock(return_value=httpx.Response(200, json={"ok": True}))
            result = await base_client._request("GET", "/v1/recovery")
            assert result == {"ok": True}
            assert base_client.breaker.state == CircuitState.CLOSED

    async def test_attest_never_leaks_token(self, base_client):
        att = await base_client.attest()
        assert att["auth_configured"] is True
        # token value itself must NOT be in attestation
        assert "secret-token" not in str(att)


# ---------------------------------------------------------------------------
# HardenedAIMClient
# ---------------------------------------------------------------------------


class TestAIM:
    async def test_get_credential_found(self):
        client = HardenedAIMClient(_cfg("aim"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.get("/v1/credentials/agent-01").mock(
                    return_value=httpx.Response(
                        200,
                        json={
                            "credential": {
                                "agentId": "agent-01",
                                "status": "active",
                                "permittedOperations": ["modelInvoke"],
                            }
                        },
                    )
                )
                cred = await client.get_credential("agent-01")
                assert cred["agentId"] == "agent-01"
                assert cred["status"] == "active"
        finally:
            await client.close()

    async def test_get_credential_404_returns_none(self):
        client = HardenedAIMClient(_cfg("aim"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.get("/v1/credentials/missing").mock(
                    return_value=httpx.Response(404, text="not found")
                )
                cred = await client.get_credential("missing")
                assert cred is None
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# HardenedOPAClient
# ---------------------------------------------------------------------------


class TestOPA:
    async def test_evaluate_allow_decision(self):
        client = HardenedOPAClient(_cfg("opa"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.post("/v1/data/arhiax/b14/decision").mock(
                    return_value=httpx.Response(
                        200,
                        json={"result": {"allow": True, "deny": False, "reasons": []}},
                    )
                )
                result = await client.evaluate_bundle("B14", {"agentId": "a1"})
                assert result["allow"] is True
                assert result["deny"] is False
        finally:
            await client.close()

    async def test_evaluate_deny_with_reasons(self):
        client = HardenedOPAClient(_cfg("opa"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.post("/v1/data/arhiax/b16/decision").mock(
                    return_value=httpx.Response(
                        200,
                        json={
                            "result": {
                                "allow": False,
                                "deny": True,
                                "reasons": ["OPERATION_NOT_PERMITTED"],
                            }
                        },
                    )
                )
                result = await client.evaluate_bundle("B16", {"operation": "fileWrite"})
                assert result["deny"] is True
                assert "OPERATION_NOT_PERMITTED" in result["reasons"]
        finally:
            await client.close()

    async def test_bundle_id_is_normalized(self):
        client = HardenedOPAClient(_cfg("opa"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                route = mock.post("/v1/data/arhiax/b03/decision").mock(
                    return_value=httpx.Response(
                        200, json={"result": {"allow": True, "deny": False, "reasons": []}}
                    )
                )
                await client.evaluate_bundle("B-03", {})
                assert route.call_count == 1
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# HardenedAUTClient
# ---------------------------------------------------------------------------


class TestAUT:
    async def test_check_autonomy_allowed(self):
        client = HardenedAUTClient(_cfg("aut"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.post("/v1/autonomy/check").mock(
                    return_value=httpx.Response(
                        200,
                        json={"allowed": True, "grantedLevel": 2, "ceiling": 3},
                    )
                )
                result = await client.check_autonomy("agent-01", "modelInvoke", 2)
                assert result["allowed"] is True
                assert result["granted_level"] == 2
                assert result["ceiling"] == 3
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# HardenedBBRClient — SOFT-FAIL client
# ---------------------------------------------------------------------------


class TestBBR:
    async def test_score_observation_returns_anomaly(self):
        client = HardenedBBRClient(_cfg("bbr"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.post("/v1/baseline/agent-01/score").mock(
                    return_value=httpx.Response(
                        200,
                        json={
                            "anomalyScore": 0.23,
                            "baselineStatus": "nominal",
                            "percentile": 78.0,
                        },
                    )
                )
                result = await client.score_observation("agent-01", {"tokens": 150})
                assert result["anomaly_score"] == 0.23
                assert result["baseline_status"] == "nominal"
        finally:
            await client.close()

    async def test_bbr_unavailable_still_raises(self):
        """BBR is SOFT-FAIL at the ATK layer, but the client itself still
        raises UpstreamUnavailableError. The ATK service catches it and
        translates to ALLOW_WITH_MONITORING per §7."""
        client = HardenedBBRClient(_cfg("bbr"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.post("/v1/baseline/agent-01/score").mock(
                    return_value=httpx.Response(503)
                )
                with pytest.raises(UpstreamUnavailableError):
                    await client.score_observation("agent-01", {})
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# HardenedEGAClient
# ---------------------------------------------------------------------------


class TestEGA:
    async def test_append_returns_evidence_ref(self):
        client = HardenedEGAClient(_cfg("ega"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.post("/v1/evidence").mock(
                    return_value=httpx.Response(
                        200,
                        json={
                            "evidenceRef": "ega:seq:00042",
                            "sequenceNumber": 42,
                            "timestamp": "2026-04-07T22:00:00Z",
                        },
                    )
                )
                result = await client.append({"envelopeId": "env-x", "event": "envelopeStart"})
                assert result["evidence_ref"] == "ega:seq:00042"
                assert result["sequence_number"] == 42
        finally:
            await client.close()

    async def test_get_404_returns_none(self):
        client = HardenedEGAClient(_cfg("ega"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.get("/v1/evidence/ega:seq:99999").mock(
                    return_value=httpx.Response(404)
                )
                result = await client.get("ega:seq:99999")
                assert result is None
        finally:
            await client.close()

    async def test_query_by_envelope(self):
        client = HardenedEGAClient(_cfg("ega"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.get("/v1/evidence").mock(
                    return_value=httpx.Response(
                        200,
                        json={
                            "entries": [
                                {"evidenceRef": "ega:seq:1", "event": "envelopeStart"},
                                {"evidenceRef": "ega:seq:2", "event": "envelopeEnd"},
                            ]
                        },
                    )
                )
                entries = await client.query_by_envelope("env-x")
                assert len(entries) == 2
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# HardenedHICClient
# ---------------------------------------------------------------------------


class TestHIC:
    async def test_open_ticket_returns_url(self):
        client = HardenedHICClient(_cfg("hic"))
        try:
            with respx.mock(base_url="https://upstream.test") as mock:
                mock.post("/v1/tickets").mock(
                    return_value=httpx.Response(
                        200,
                        json={
                            "ticketId": "HIC-2026-0042",
                            "url": "https://hic.arhiax.example/tickets/HIC-2026-0042",
                            "createdAt": "2026-04-07T22:00:00Z",
                        },
                    )
                )
                result = await client.open_ticket(
                    envelope_id="env-x",
                    reason="prompt_injection_suspected",
                    severity="high",
                    context={"score": 0.92},
                )
                assert result["ticket_id"] == "HIC-2026-0042"
                assert "tickets" in result["url"]
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# ClientConfig.from_env
# ---------------------------------------------------------------------------


class TestClientConfigFromEnv:
    def test_from_env_requires_url(self, monkeypatch):
        monkeypatch.delenv("TEST_URL", raising=False)
        with pytest.raises(ValueError, match="TEST_URL"):
            ClientConfig.from_env("test", "TEST_")

    def test_from_env_reads_all_fields(self, monkeypatch):
        monkeypatch.setenv("TEST_URL", "https://upstream.example")
        monkeypatch.setenv("TEST_TOKEN", "abc123")
        monkeypatch.setenv("TEST_TIMEOUT", "7.5")
        monkeypatch.setenv("TEST_MAX_RETRIES", "5")
        monkeypatch.setenv("TEST_VERIFY_TLS", "false")
        cfg = ClientConfig.from_env("test", "TEST_")
        assert cfg.base_url == "https://upstream.example"
        assert cfg.auth_token == "abc123"
        assert cfg.timeout_seconds == 7.5
        assert cfg.max_retries == 5
        assert cfg.verify_tls is False

    def test_from_env_strips_trailing_slash(self, monkeypatch):
        monkeypatch.setenv("TEST_URL", "https://upstream.example/")
        cfg = ClientConfig.from_env("test", "TEST_")
        assert cfg.base_url == "https://upstream.example"


# ---------------------------------------------------------------------------
# Mode selector
# ---------------------------------------------------------------------------


class TestModeSelector:
    def test_default_mode_is_development(self, monkeypatch):
        monkeypatch.delenv("ARHIAX_MODE", raising=False)
        from client_mode import get_mode, ARHIAXMode
        assert get_mode() == ARHIAXMode.DEVELOPMENT

    def test_unknown_mode_falls_back_to_development(self, monkeypatch):
        monkeypatch.setenv("ARHIAX_MODE", "yolo")
        from client_mode import get_mode, ARHIAXMode
        assert get_mode() == ARHIAXMode.DEVELOPMENT

    def test_production_mode_recognized(self, monkeypatch):
        monkeypatch.setenv("ARHIAX_MODE", "production")
        from client_mode import get_mode, ARHIAXMode
        assert get_mode() == ARHIAXMode.PRODUCTION

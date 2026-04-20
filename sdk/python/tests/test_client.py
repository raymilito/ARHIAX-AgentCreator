"""Tests del GatewayClient y circuit breaker del SDK ARHIAX."""
import sys
import os
import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arhiax.client import GatewayClient, _CircuitBreaker
from arhiax.exceptions import ARHIAXServiceUnavailable


# ── CircuitBreaker ────────────────────────────────────────────────────────────

class TestCircuitBreaker:
    def setup_method(self):
        self.cb = _CircuitBreaker(fail_threshold=3, recovery_s=30.0)

    def test_initial_state_closed(self):
        assert self.cb.state == "CLOSED"
        assert self.cb.failure_count == 0

    def test_record_failure_increments(self):
        self.cb.record_failure()
        assert self.cb.failure_count == 1
        assert self.cb.state == "CLOSED"

    def test_opens_after_threshold(self):
        for _ in range(3):
            self.cb.record_failure()
        assert self.cb.state == "OPEN"

    def test_success_resets_failures(self):
        self.cb.record_failure()
        self.cb.record_failure()
        self.cb.record_success()
        assert self.cb.failure_count == 0
        assert self.cb.state == "CLOSED"

    def test_open_state_is_open(self):
        for _ in range(3):
            self.cb.record_failure()
        assert self.cb.is_open()

    def test_closed_state_is_not_open(self):
        assert not self.cb.is_open()

    def test_recovers_after_timeout(self):
        import time
        self.cb = _CircuitBreaker(fail_threshold=2, recovery_s=0.01)
        self.cb.record_failure()
        self.cb.record_failure()
        assert self.cb.state == "OPEN"
        time.sleep(0.05)
        assert not self.cb.is_open()  # ha expirado → HALF_OPEN


# ── GatewayClient ─────────────────────────────────────────────────────────────

class TestGatewayClient:
    def setup_method(self):
        self.client = GatewayClient(gateway_url="http://gw-test:8080")

    @pytest.mark.asyncio
    async def test_decide_allow(self):
        mock_response = {
            "allow": True,
            "reasons": [],
            "obligations": [{"type": "rate_limit", "value": 100}],
            "evidence_id": "ev-001",
            "error": None,
        }

        async def fake_post(*args, **kwargs):
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = mock_response
            return m

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(post=AsyncMock(side_effect=fake_post))
            )
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await self.client.decide(
                subject="agent-001",
                action="toolCall",
                resource="consultar_db",
                context={},
            )

        assert result["allow"] is True
        assert result["evidence_id"] == "ev-001"

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_on_failures(self):
        """Después de fail_threshold fallos, el circuito debe abrirse."""
        self.client._breaker = _CircuitBreaker(fail_threshold=2, recovery_s=60.0)

        async def failing_post(*args, **kwargs):
            raise Exception("Connection refused")

        for _ in range(2):
            try:
                with patch("httpx.AsyncClient") as mock_client:
                    mock_client.return_value.__aenter__ = AsyncMock(
                        return_value=MagicMock(post=AsyncMock(side_effect=failing_post))
                    )
                    mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
                    await self.client.decide("a", "b", "c", {})
            except (ARHIAXServiceUnavailable, Exception):
                pass

        assert self.client._breaker.state == "OPEN"

    @pytest.mark.asyncio
    async def test_open_circuit_raises_immediately(self):
        """Con circuito OPEN, debe fallar sin intentar la llamada HTTP."""
        self.client._breaker = _CircuitBreaker(fail_threshold=1, recovery_s=3600.0)
        self.client._breaker.record_failure()  # Abre el circuito

        with pytest.raises(ARHIAXServiceUnavailable) as exc_info:
            await self.client.decide("a", "toolCall", "b", {})

        assert "Gateway" in str(exc_info.value) or "Circuit" in str(exc_info.value)


# ── AIMClient ─────────────────────────────────────────────────────────────────

class TestAIMClient:
    def setup_method(self):
        from arhiax.client import AIMClient
        self.client = AIMClient(aim_url="http://aim-test:8200")

    @pytest.mark.asyncio
    async def test_get_credential_ok(self):
        mock_data = {
            "agent_id": "agent-001",
            "name": "Test",
            "supervisor_id": "sup-001",
            "department_id": "dept-x",
            "authorization_boundary_id": "default",
            "autonomy_level": "A0",
            "credential_issued_at": "2026-04-19T12:00:00",
            "credential_expires_at": "2026-07-18T12:00:00",
            "rotation_policy": "90d",
            "lifecycle_state": "ACTIVE",
            "parent_chain_hmac": "sha256:abc",
            "permitted_tools": [],
            "permitted_data_scopes": [],
            "permitted_operations": ["toolCall"],
        }

        async def fake_get(*args, **kwargs):
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = mock_data
            return m

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(side_effect=fake_get))
            )
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

            from arhiax.models import Credential
            cred = await self.client.get_credential("agent-001")

        assert cred.agent_id == "agent-001"
        assert cred.lifecycle_state == "ACTIVE"

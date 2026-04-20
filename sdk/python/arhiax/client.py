"""Cliente HTTP del SDK ARHIAX.
Comunicación con Gateway, AIM, HIC y BBR con retry y circuit breaker.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Dict, Optional

import httpx

from .exceptions import ARHIAXServiceUnavailable
from .models import Credential, GovernanceDecision, DecisionOutcome


class _CircuitBreaker:
    """Circuit breaker simple: CLOSED → OPEN → HALF_OPEN."""

    def __init__(self, fail_threshold: int = 5, recovery_s: float = 30.0):
        self._failures = 0
        self._threshold = fail_threshold
        self._recovery = recovery_s
        self._opened_at: Optional[float] = None

    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if time.monotonic() - self._opened_at > self._recovery:
            self._opened_at = None
            self._failures = 0
            return False
        return True

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._opened_at = time.monotonic()

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None


class GatewayClient:
    """Cliente del Gateway ARHIAX — envía decisiones con retry automático."""

    def __init__(self, gateway_url: str, timeout: float = 10.0, max_retries: int = 3):
        self._url = gateway_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._cb = _CircuitBreaker()

    async def decide(
        self,
        subject: str,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GovernanceDecision:
        if self._cb.is_open():
            raise ARHIAXServiceUnavailable("gateway", "Circuit breaker abierto")

        payload = {
            "subject": subject,
            "action": action,
            "resource": resource,
            "context": {"invocationId": str(uuid.uuid4()), **context},
        }

        last_exc: Optional[Exception] = None
        for attempt in range(self._max_retries):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    r = await client.post(f"{self._url}/v1/decide", json=payload)
                self._cb.record_success()

                data = r.json()
                allow = data.get("allow", False)
                reasons = data.get("reasons", [])
                obligations = data.get("obligations", [])
                evidence_id = data.get("evidence_id", "")

                if not allow:
                    if "INJECTION_DETECTED" in reasons:
                        outcome = DecisionOutcome.DENY_WITH_INCIDENT
                    else:
                        outcome = DecisionOutcome.DENY
                else:
                    outcome = DecisionOutcome.ALLOW

                return GovernanceDecision(
                    allow=allow, outcome=outcome,
                    reasons=reasons, obligations=obligations,
                    evidence_id=evidence_id,
                )
            except httpx.TimeoutException as exc:
                last_exc = exc
                self._cb.record_failure()
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
            except Exception as exc:
                last_exc = exc
                self._cb.record_failure()
                break

        raise ARHIAXServiceUnavailable("gateway", str(last_exc))


class AIMClient:
    """Cliente del AIM Service — obtiene y actualiza credenciales."""

    def __init__(self, aim_url: str, timeout: float = 5.0):
        self._url = aim_url.rstrip("/")
        self._timeout = timeout

    async def get_credential(self, agent_id: str) -> Credential:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                r = await client.get(f"{self._url}/v1/credentials/{agent_id}")
            if r.status_code == 404:
                raise ARHIAXServiceUnavailable("aim", f"Agente {agent_id} no encontrado")
            r.raise_for_status()
            return Credential(**r.json())
        except httpx.HTTPError as exc:
            raise ARHIAXServiceUnavailable("aim", str(exc))


class HICClient:
    """Cliente del HIC Service — abre tickets de aprobación humana."""

    def __init__(self, hic_url: str, timeout: float = 5.0):
        self._url = hic_url.rstrip("/")
        self._timeout = timeout

    async def open_ticket(
        self, agent_id: str, action: str, resource: str,
        reason: str, severity: str = "MEDIUM", context: dict = {},
    ) -> str:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                r = await client.post(f"{self._url}/v1/tickets", json={
                    "agent_id": agent_id, "action": action,
                    "resource": resource, "reason": reason,
                    "severity": severity, "context": context,
                })
            r.raise_for_status()
            return r.json().get("ticket_id", "")
        except Exception:
            return ""

    async def get_ticket_status(self, ticket_id: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                r = await client.get(f"{self._url}/v1/tickets/{ticket_id}")
            return r.json().get("status", "UNKNOWN")
        except Exception:
            return "UNKNOWN"


class BBRClient:
    """Cliente del BBR Service — registra observaciones de comportamiento."""

    def __init__(self, bbr_url: str, timeout: float = 5.0):
        self._url = bbr_url.rstrip("/")
        self._timeout = timeout

    async def record_observation(
        self, agent_id: str, operation_type: str,
        duration_ms: float, token_count: int = 0,
        outcome: str = "ALLOW", tool_name: Optional[str] = None,
    ) -> None:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                await client.post(f"{self._url}/v1/baseline/{agent_id}/observe", json={
                    "agent_id": agent_id, "operation_type": operation_type,
                    "duration_ms": duration_ms, "token_count": token_count,
                    "outcome": outcome, "tool_name": tool_name,
                })
        except Exception:
            pass  # BBR es fail-open

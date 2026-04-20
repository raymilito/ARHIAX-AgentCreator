"""
ARHIAX v11.4 — Hardened Client Base
====================================

Base class for all production HTTP clients that replace the InMemory* stubs
when ARHIAX_MODE=production.

Provides:
  - httpx AsyncClient with configurable timeouts and connection pooling
  - tenacity retry with exponential backoff + jitter
  - Circuit breaker (closed → open → half_open) with failure threshold
  - Prometheus instrumentation (requests_total, latency_seconds, circuit_state)
  - Structured logging with correlation IDs
  - Secret injection via environment variables (never hardcoded)
  - Fail-closed semantics: on unrecoverable error, raises ARHIAXClientError
    which the ATK service MUST translate to DENY_WITH_INCIDENT per §7 of the
    MasterSpec fail-mode matrix.

Spec anchors:
  - TR-2026-034 MasterSpec §7 (Failure Modes)
  - TR-2026-033 Phase3 §6 (Integration Contracts)
  - ATK-C07 (startup attestation of configured endpoints)

Author: Sinergia Consulting Group S.A.S.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

import httpx
from prometheus_client import Counter, Gauge, Histogram
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

logger = logging.getLogger("arhiax.clients")

# ---------------------------------------------------------------------------
# Prometheus metrics — registered once at module import
# ---------------------------------------------------------------------------

CLIENT_REQUESTS_TOTAL = Counter(
    "arhiax_client_requests_total",
    "Total HTTP requests issued by hardened clients",
    ["client", "method", "endpoint", "outcome"],
)

CLIENT_LATENCY_SECONDS = Histogram(
    "arhiax_client_latency_seconds",
    "Latency of hardened client requests in seconds",
    ["client", "method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

CLIENT_CIRCUIT_STATE = Gauge(
    "arhiax_client_circuit_state",
    "Circuit breaker state: 0=closed, 1=half_open, 2=open",
    ["client"],
)

CLIENT_RETRY_TOTAL = Counter(
    "arhiax_client_retry_total",
    "Total retry attempts across hardened clients",
    ["client", "endpoint"],
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ARHIAXClientError(Exception):
    """Base exception for all hardened client failures."""

    def __init__(self, message: str, client: str, endpoint: str, cause: Optional[Exception] = None):
        super().__init__(message)
        self.client = client
        self.endpoint = endpoint
        self.cause = cause


class CircuitOpenError(ARHIAXClientError):
    """Raised when a request is short-circuited because the breaker is open."""


class UpstreamUnavailableError(ARHIAXClientError):
    """Raised when upstream returns 5xx or connection fails after all retries."""


class UpstreamContractError(ARHIAXClientError):
    """Raised when upstream returns a 4xx that the client cannot handle
    (malformed request on our side, or schema mismatch)."""


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class CircuitState(Enum):
    CLOSED = 0
    HALF_OPEN = 1
    OPEN = 2


@dataclass
class CircuitBreaker:
    """Simple in-process circuit breaker.

    State machine:
        CLOSED  → OPEN       after `failure_threshold` consecutive failures
        OPEN    → HALF_OPEN  after `reset_timeout_seconds` elapsed
        HALF_OPEN → CLOSED   on first success
        HALF_OPEN → OPEN     on any failure
    """

    name: str
    failure_threshold: int = 5
    reset_timeout_seconds: float = 30.0
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    opened_at: Optional[float] = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def before_call(self) -> None:
        async with self._lock:
            if self.state == CircuitState.OPEN:
                assert self.opened_at is not None
                if time.monotonic() - self.opened_at >= self.reset_timeout_seconds:
                    logger.info(f"circuit[{self.name}] OPEN → HALF_OPEN (reset timeout elapsed)")
                    self.state = CircuitState.HALF_OPEN
                    CLIENT_CIRCUIT_STATE.labels(client=self.name).set(CircuitState.HALF_OPEN.value)
                else:
                    raise CircuitOpenError(
                        f"circuit breaker OPEN for {self.name}",
                        client=self.name,
                        endpoint="<breaker>",
                    )

    async def on_success(self) -> None:
        async with self._lock:
            if self.state != CircuitState.CLOSED:
                logger.info(f"circuit[{self.name}] {self.state.name} → CLOSED")
            self.state = CircuitState.CLOSED
            self.consecutive_failures = 0
            self.opened_at = None
            CLIENT_CIRCUIT_STATE.labels(client=self.name).set(CircuitState.CLOSED.value)

    async def on_failure(self) -> None:
        async with self._lock:
            self.consecutive_failures += 1
            if self.state == CircuitState.HALF_OPEN or self.consecutive_failures >= self.failure_threshold:
                if self.state != CircuitState.OPEN:
                    logger.warning(
                        f"circuit[{self.name}] → OPEN (failures={self.consecutive_failures})"
                    )
                self.state = CircuitState.OPEN
                self.opened_at = time.monotonic()
                CLIENT_CIRCUIT_STATE.labels(client=self.name).set(CircuitState.OPEN.value)


# ---------------------------------------------------------------------------
# Hardened base client
# ---------------------------------------------------------------------------


@dataclass
class ClientConfig:
    """Configuration for a hardened client, sourced from env vars."""

    name: str
    base_url: str
    auth_token: Optional[str] = None  # Bearer token; sourced from env var
    timeout_seconds: float = 5.0
    connect_timeout_seconds: float = 2.0
    max_retries: int = 3
    retry_min_wait: float = 0.1
    retry_max_wait: float = 2.0
    circuit_failure_threshold: int = 5
    circuit_reset_seconds: float = 30.0
    pool_max_connections: int = 20
    pool_max_keepalive: int = 10
    verify_tls: bool = True

    @classmethod
    def from_env(cls, name: str, prefix: str) -> "ClientConfig":
        """Build config from env vars prefixed with e.g. ARHIAX_AIM_.

        Required:   {prefix}URL
        Optional:   {prefix}TOKEN, {prefix}TIMEOUT, {prefix}VERIFY_TLS, ...
        """
        base_url = os.environ.get(f"{prefix}URL")
        if not base_url:
            raise ValueError(
                f"missing required env var {prefix}URL for hardened client '{name}'"
            )
        return cls(
            name=name,
            base_url=base_url.rstrip("/"),
            auth_token=os.environ.get(f"{prefix}TOKEN"),
            timeout_seconds=float(os.environ.get(f"{prefix}TIMEOUT", "5.0")),
            connect_timeout_seconds=float(os.environ.get(f"{prefix}CONNECT_TIMEOUT", "2.0")),
            max_retries=int(os.environ.get(f"{prefix}MAX_RETRIES", "3")),
            retry_min_wait=float(os.environ.get(f"{prefix}RETRY_MIN_WAIT", "0.1")),
            retry_max_wait=float(os.environ.get(f"{prefix}RETRY_MAX_WAIT", "2.0")),
            circuit_failure_threshold=int(
                os.environ.get(f"{prefix}CIRCUIT_THRESHOLD", "5")
            ),
            circuit_reset_seconds=float(os.environ.get(f"{prefix}CIRCUIT_RESET", "30.0")),
            pool_max_connections=int(os.environ.get(f"{prefix}POOL_MAX", "20")),
            pool_max_keepalive=int(os.environ.get(f"{prefix}POOL_KEEPALIVE", "10")),
            verify_tls=os.environ.get(f"{prefix}VERIFY_TLS", "true").lower() == "true",
        )


class HardenedClient:
    """Base class for all hardened HTTP clients.

    Subclasses implement their domain API by calling `self._request(...)`.
    The base class handles:
      - httpx AsyncClient lifecycle
      - tenacity retry on transient failures (5xx, connect errors, timeouts)
      - circuit breaker coordination
      - prometheus metrics
      - auth header injection
      - fail-closed translation (raises ARHIAXClientError on any unrecoverable)
    """

    def __init__(self, config: ClientConfig):
        self.config = config
        self.breaker = CircuitBreaker(
            name=config.name,
            failure_threshold=config.circuit_failure_threshold,
            reset_timeout_seconds=config.circuit_reset_seconds,
        )
        CLIENT_CIRCUIT_STATE.labels(client=config.name).set(CircuitState.CLOSED.value)

        timeout = httpx.Timeout(
            timeout=config.timeout_seconds,
            connect=config.connect_timeout_seconds,
        )
        limits = httpx.Limits(
            max_connections=config.pool_max_connections,
            max_keepalive_connections=config.pool_max_keepalive,
        )
        headers: Dict[str, str] = {
            "User-Agent": f"arhiax-atk/{os.environ.get('ARHIAX_VERSION', '11.4')}",
            "Accept": "application/json",
        }
        if config.auth_token:
            headers["Authorization"] = f"Bearer {config.auth_token}"

        self._http = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=timeout,
            limits=limits,
            headers=headers,
            verify=config.verify_tls,
        )
        logger.info(
            f"hardened client initialized: name={config.name} url={config.base_url} "
            f"timeout={config.timeout_seconds}s retries={config.max_retries} tls={config.verify_tls}"
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def attest(self) -> Dict[str, Any]:
        """ATK-C07 startup attestation. Returns endpoint metadata without secrets."""
        return {
            "client": self.config.name,
            "base_url": self.config.base_url,
            "auth_configured": bool(self.config.auth_token),
            "verify_tls": self.config.verify_tls,
            "circuit_state": self.breaker.state.name,
            "timeout_seconds": self.config.timeout_seconds,
            "max_retries": self.config.max_retries,
        }

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Issue an HTTP request with retry + circuit breaker + metrics.

        Raises:
            CircuitOpenError         — breaker is open, short-circuited
            UpstreamUnavailableError — 5xx or connect failure after all retries
            UpstreamContractError    — 4xx that we cannot recover from
        """
        await self.breaker.before_call()

        headers: Dict[str, str] = {}
        if correlation_id:
            headers["X-ARHIAX-Correlation-Id"] = correlation_id

        endpoint_label = path.split("?")[0]  # no query string in metric label
        start = time.perf_counter()
        attempts = 0

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.config.max_retries),
                wait=wait_exponential_jitter(
                    initial=self.config.retry_min_wait,
                    max=self.config.retry_max_wait,
                ),
                retry=retry_if_exception_type(
                    (
                        httpx.ConnectError,
                        httpx.ReadTimeout,
                        httpx.WriteTimeout,
                        httpx.PoolTimeout,
                        UpstreamUnavailableError,
                    )
                ),
                reraise=True,
            ):
                with attempt:
                    attempts += 1
                    if attempts > 1:
                        CLIENT_RETRY_TOTAL.labels(
                            client=self.config.name, endpoint=endpoint_label
                        ).inc()
                    response = await self._http.request(
                        method=method,
                        url=path,
                        json=json_body,
                        params=params,
                        headers=headers,
                    )
                    if 500 <= response.status_code < 600:
                        raise UpstreamUnavailableError(
                            f"upstream 5xx: {response.status_code}",
                            client=self.config.name,
                            endpoint=endpoint_label,
                        )
                    if 400 <= response.status_code < 500:
                        raise UpstreamContractError(
                            f"upstream 4xx: {response.status_code} body={response.text[:200]}",
                            client=self.config.name,
                            endpoint=endpoint_label,
                        )
                    response.raise_for_status()
                    data = response.json()

            # success path
            await self.breaker.on_success()
            elapsed = time.perf_counter() - start
            CLIENT_LATENCY_SECONDS.labels(
                client=self.config.name, method=method, endpoint=endpoint_label
            ).observe(elapsed)
            CLIENT_REQUESTS_TOTAL.labels(
                client=self.config.name,
                method=method,
                endpoint=endpoint_label,
                outcome="success",
            ).inc()
            return data

        except UpstreamContractError:
            # 4xx is a contract error, not a transient failure — do NOT trip the breaker
            CLIENT_REQUESTS_TOTAL.labels(
                client=self.config.name,
                method=method,
                endpoint=endpoint_label,
                outcome="contract_error",
            ).inc()
            raise
        except (RetryError, UpstreamUnavailableError, httpx.RequestError) as exc:
            await self.breaker.on_failure()
            CLIENT_REQUESTS_TOTAL.labels(
                client=self.config.name,
                method=method,
                endpoint=endpoint_label,
                outcome="upstream_unavailable",
            ).inc()
            raise UpstreamUnavailableError(
                f"upstream unavailable after {attempts} attempts: {exc}",
                client=self.config.name,
                endpoint=endpoint_label,
                cause=exc if isinstance(exc, Exception) else None,
            ) from exc

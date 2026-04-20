"""
ARHIAX v11.4 — Hardened Production Clients
===========================================

Concrete HTTP clients for the 6 external dependencies of the ATK service:

    HardenedAIMClient  — Agent Identity Management (B14 credentials)
    HardenedOPAClient  — Open Policy Agent (19 bundles evaluation)
    HardenedAUTClient  — Autonomy service (autonomy level checks)
    HardenedBBRClient  — Behavioral Baseline Registry (anomaly scoring)
    HardenedEGAClient  — Evidence Generation Architecture (ledger append)
    HardenedHICClient  — Human-in-the-Loop Console (escalation tickets)

Each client exposes the same surface as its InMemory* counterpart from
arhiax_atk_service.py, so the ATKService factory can swap implementations
based on ARHIAX_MODE without touching business logic.

Env var schema (per client):
    ARHIAX_AIM_URL          → base URL (required)
    ARHIAX_AIM_TOKEN        → bearer token (optional, read from secret)
    ARHIAX_AIM_TIMEOUT      → request timeout seconds (default 5.0)
    ARHIAX_AIM_MAX_RETRIES  → retry attempts (default 3)
    ARHIAX_AIM_VERIFY_TLS   → TLS verification (default true)
    ... (same pattern for OPA, AUT, BBR, EGA, HIC)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from hardened_base import (
    ClientConfig,
    HardenedClient,
    UpstreamContractError,
)

logger = logging.getLogger("arhiax.clients")


# ---------------------------------------------------------------------------
# AIM — Agent Identity Management
# ---------------------------------------------------------------------------


class HardenedAIMClient(HardenedClient):
    """Backs B14 AIM Identity bundle.

    Contract:
        get_credential(agent_id) -> dict | None
    """

    ENV_PREFIX = "ARHIAX_AIM_"

    @classmethod
    def from_env(cls) -> "HardenedAIMClient":
        return cls(ClientConfig.from_env("aim", cls.ENV_PREFIX))

    async def get_credential(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Fetch AIM credential for an agent.

        Returns None if credential not found (404). Raises on any other error,
        which the ATK translates to DENY_WITH_INCIDENT.
        """
        try:
            data = await self._request(
                "GET",
                f"/v1/credentials/{agent_id}",
            )
            return data.get("credential")
        except UpstreamContractError as exc:
            # 404 = not found, return None; other 4xx = re-raise
            if "404" in str(exc):
                return None
            raise


# ---------------------------------------------------------------------------
# OPA — Open Policy Agent
# ---------------------------------------------------------------------------


class HardenedOPAClient(HardenedClient):
    """Evaluates the 19 ARHIAX bundles against an input document.

    Contract:
        evaluate_bundle(bundle_id, input_doc) -> dict with 'allow', 'deny', 'reasons'
    """

    ENV_PREFIX = "ARHIAX_OPA_"

    @classmethod
    def from_env(cls) -> "HardenedOPAClient":
        return cls(ClientConfig.from_env("opa", cls.ENV_PREFIX))

    async def evaluate_bundle(
        self, bundle_id: str, input_doc: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Call OPA Data API: POST /v1/data/arhiax/{bundle}/decision

        The OPA server must have the arhiax bundles loaded. The decision
        endpoint returns {"result": {"allow": bool, "deny": bool, "reasons": [...]}}.
        """
        bundle_path = bundle_id.lower().replace("-", "").replace("_", "")
        response = await self._request(
            "POST",
            f"/v1/data/arhiax/{bundle_path}/decision",
            json_body={"input": input_doc},
        )
        result = response.get("result", {})
        if not isinstance(result, dict):
            raise UpstreamContractError(
                f"OPA returned unexpected result shape for {bundle_id}: {result}",
                client=self.config.name,
                endpoint=f"/v1/data/arhiax/{bundle_path}/decision",
            )
        return {
            "allow": bool(result.get("allow", False)),
            "deny": bool(result.get("deny", False)),
            "reasons": list(result.get("reasons", [])),
        }


# ---------------------------------------------------------------------------
# AUT — Autonomy service
# ---------------------------------------------------------------------------


class HardenedAUTClient(HardenedClient):
    """Checks autonomy levels for the requesting agent on a given operation.

    Contract:
        check_autonomy(agent_id, operation, requested_level) -> dict with 'allowed', 'granted_level'
    """

    ENV_PREFIX = "ARHIAX_AUT_"

    @classmethod
    def from_env(cls) -> "HardenedAUTClient":
        return cls(ClientConfig.from_env("aut", cls.ENV_PREFIX))

    async def check_autonomy(
        self,
        agent_id: str,
        operation: str,
        requested_level: int,
    ) -> Dict[str, Any]:
        response = await self._request(
            "POST",
            "/v1/autonomy/check",
            json_body={
                "agentId": agent_id,
                "operation": operation,
                "requestedLevel": requested_level,
            },
        )
        return {
            "allowed": bool(response.get("allowed", False)),
            "granted_level": int(response.get("grantedLevel", 0)),
            "ceiling": int(response.get("ceiling", 0)),
        }


# ---------------------------------------------------------------------------
# BBR — Behavioral Baseline Registry
# ---------------------------------------------------------------------------


class HardenedBBRClient(HardenedClient):
    """Scores a behavioral observation against the agent's baseline.

    Contract:
        score_observation(agent_id, features) -> dict with 'anomaly_score', 'baseline_status'

    Per §7 of MasterSpec: BBR is SOFT-FAIL. If unreachable, ATK returns
    ALLOW_WITH_MONITORING instead of DENY_WITH_INCIDENT. This means the
    caller in ATK must catch UpstreamUnavailableError from this client
    specifically and not promote it to an envelope failure.
    """

    ENV_PREFIX = "ARHIAX_BBR_"

    @classmethod
    def from_env(cls) -> "HardenedBBRClient":
        return cls(ClientConfig.from_env("bbr", cls.ENV_PREFIX))

    async def score_observation(
        self,
        agent_id: str,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        response = await self._request(
            "POST",
            f"/v1/baseline/{agent_id}/score",
            json_body={"features": features},
        )
        return {
            "anomaly_score": float(response.get("anomalyScore", 0.0)),
            "baseline_status": response.get("baselineStatus", "unknown"),
            "percentile": float(response.get("percentile", 0.0)),
        }


# ---------------------------------------------------------------------------
# EGA — Evidence Generation Architecture
# ---------------------------------------------------------------------------


class HardenedEGAClient(HardenedClient):
    """Appends evidence entries to the ARHIAX immutable ledger.

    Contract:
        append(entry) -> dict with 'evidenceRef', 'sequenceNumber'
        get(evidence_ref) -> dict (for audit queries)
    """

    ENV_PREFIX = "ARHIAX_EGA_"

    @classmethod
    def from_env(cls) -> "HardenedEGAClient":
        return cls(ClientConfig.from_env("ega", cls.ENV_PREFIX))

    async def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        response = await self._request(
            "POST",
            "/v1/evidence",
            json_body=entry,
        )
        return {
            "evidence_ref": response.get("evidenceRef"),
            "sequence_number": int(response.get("sequenceNumber", 0)),
            "timestamp": response.get("timestamp"),
        }

    async def get(self, evidence_ref: str) -> Optional[Dict[str, Any]]:
        try:
            return await self._request("GET", f"/v1/evidence/{evidence_ref}")
        except UpstreamContractError as exc:
            if "404" in str(exc):
                return None
            raise

    async def query_by_envelope(self, envelope_id: str) -> List[Dict[str, Any]]:
        response = await self._request(
            "GET",
            "/v1/evidence",
            params={"envelopeId": envelope_id},
        )
        return list(response.get("entries", []))


# ---------------------------------------------------------------------------
# HIC — Human-in-the-Loop Console
# ---------------------------------------------------------------------------


class HardenedHICClient(HardenedClient):
    """Opens escalation tickets for human-in-the-loop review.

    Contract:
        open_ticket(envelope_id, reason, severity, context) -> dict with 'ticketId', 'url'
        get_ticket_status(ticket_id) -> dict with 'status', 'decision', 'reviewer'
    """

    ENV_PREFIX = "ARHIAX_HIC_"

    @classmethod
    def from_env(cls) -> "HardenedHICClient":
        return cls(ClientConfig.from_env("hic", cls.ENV_PREFIX))

    async def open_ticket(
        self,
        envelope_id: str,
        reason: str,
        severity: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        response = await self._request(
            "POST",
            "/v1/tickets",
            json_body={
                "envelopeId": envelope_id,
                "reason": reason,
                "severity": severity,
                "context": context,
            },
        )
        return {
            "ticket_id": response.get("ticketId"),
            "url": response.get("url"),
            "created_at": response.get("createdAt"),
        }

    async def get_ticket_status(self, ticket_id: str) -> Dict[str, Any]:
        return await self._request("GET", f"/v1/tickets/{ticket_id}")


# ---------------------------------------------------------------------------
# Factory — one-shot initialization of all 6 clients from env
# ---------------------------------------------------------------------------


def build_all_hardened_clients() -> Dict[str, HardenedClient]:
    """Initialize all 6 hardened clients from environment variables.

    Called by the ATK service factory when ARHIAX_MODE=production.
    Raises ValueError if any required env var is missing — fail fast at startup
    is far safer than discovering missing config mid-request.
    """
    logger.info("building hardened clients for ARHIAX_MODE=production")
    clients = {
        "aim": HardenedAIMClient.from_env(),
        "opa": HardenedOPAClient.from_env(),
        "aut": HardenedAUTClient.from_env(),
        "bbr": HardenedBBRClient.from_env(),
        "ega": HardenedEGAClient.from_env(),
        "hic": HardenedHICClient.from_env(),
    }
    logger.info(f"hardened clients initialized: {list(clients.keys())}")
    return clients


async def attest_all_clients(clients: Dict[str, HardenedClient]) -> Dict[str, Any]:
    """ATK-C07 startup attestation across all 6 clients.

    Emits a single attestation document to the EGA ledger describing what
    endpoints the ATK is configured against. Useful for post-incident
    reconstruction of 'which upstream was this ATK pointed at at time T'.
    """
    attestation: Dict[str, Any] = {
        "attestationType": "ATK-C07",
        "version": "11.4",
        "clients": {},
    }
    for name, client in clients.items():
        attestation["clients"][name] = await client.attest()
    return attestation


async def close_all_clients(clients: Dict[str, HardenedClient]) -> None:
    """Graceful shutdown of all hardened clients."""
    for name, client in clients.items():
        try:
            await client.close()
            logger.info(f"hardened client closed: {name}")
        except Exception as exc:
            logger.warning(f"error closing client {name}: {exc}")

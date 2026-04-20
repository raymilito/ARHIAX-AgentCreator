"""
ARHIAX v11.4 — Agent Trust Kernel Reference Service
====================================================

File:    arhiax_atk_service.py
Anchors: TR-2026-034-ATK (ATK Reference Implementation Profile)
         ATK-C01..ATK-C07
Source:  ARHIAX_v114_ATK_Reference_Implementation_Profile.docx

Synchronous five-check envelope:
    1. Identity Resolution           (ATK-C01) -> AIM
    2. Authorization Evaluation      (ATK-C02) -> OPA bundles B14-B16, B01-B13
    3. Prompt + Output Inspection    (ATK-C03 / ATK-C04) -> heuristic policies
    4. Behavioral Baseline Check     (ATK-C05) -> BBR
    5. Autonomy Gate Evaluation      (ATK-C06) -> AUT

Six possible decision outcomes:
    ALLOW
    ALLOW_WITH_MONITORING
    ALLOW_WITH_HIC_NOTIFICATION
    DENY
    DENY_WITH_INCIDENT
    ESCALATE_TO_HUMAN

Failure-mode policy (TR-2026-034-ATK §7):
    AIM unavailable    -> DENY (IDENTITY_RESOLUTION_UNAVAILABLE)
    OPA unavailable    -> DENY (POLICY_ENGINE_UNAVAILABLE)
    BBR unavailable    -> ALLOW_WITH_MONITORING (BASELINE_CHECK_SKIPPED)  [soft]
    AUT unavailable    -> DENY (AUTONOMY_REGISTRY_UNAVAILABLE)
    EGA unavailable    -> DENY (EVIDENCE_EMISSION_UNAVAILABLE)
    HIC unavailable    -> DENY (HIC_UNAVAILABLE) on outcomes that require HIC

This module is intentionally framework-agnostic. It exposes:
    - The dataclasses (Envelope*, Credential, Decision, Evidence)
    - The pluggable client Protocols (AIMClient, OPAClient, BBRClient,
      AUTClient, EGAClient, HICClient)
    - The ATKService class implementing evaluate_envelope()
    - A minimal HTTP adapter (build_asgi_app) for production deployment

Production deployments subclass the reference clients and replace them with
hardened implementations (mTLS, retries, circuit breakers, etc.).
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Protocol

logger = logging.getLogger("arhiax.atk")


# ============================================================================
# Constants and enums
# ============================================================================

ARHIAX_VERSION = "11.4"
ATK_SERVICE_NAME = "arhiax-atk"


class OperationType(str, Enum):
    MODEL_INVOKE = "modelInvoke"
    TOOL_CALL = "toolCall"
    DATA_ACCESS = "dataAccess"
    INTER_AGENT_CALL = "interAgentCall"


class AutonomyLevel(str, Enum):
    A0 = "A0"
    A1 = "A1"
    A2 = "A2"
    A3 = "A3"
    A4 = "A4"


_AUTONOMY_RANK = {AutonomyLevel.A0: 0, AutonomyLevel.A1: 1, AutonomyLevel.A2: 2,
                  AutonomyLevel.A3: 3, AutonomyLevel.A4: 4}


# Calibrated deviation thresholds, AUT-C05.
# Value is the sigma multiple at which BBR will flag the invocation.
_BBR_THRESHOLD_BY_AUTONOMY = {
    AutonomyLevel.A0: 1.5,
    AutonomyLevel.A1: 2.0,
    AutonomyLevel.A2: 2.5,
    AutonomyLevel.A3: 3.0,
    AutonomyLevel.A4: 3.5,
}


class DecisionOutcome(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_MONITORING = "ALLOW_WITH_MONITORING"
    ALLOW_WITH_HIC_NOTIFICATION = "ALLOW_WITH_HIC_NOTIFICATION"
    DENY = "DENY"
    DENY_WITH_INCIDENT = "DENY_WITH_INCIDENT"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"


# Severity ladder used by the BBR escalation rule (Doc 6 §3.4)
_OUTCOME_LADDER = [
    DecisionOutcome.ALLOW,
    DecisionOutcome.ALLOW_WITH_MONITORING,
    DecisionOutcome.ALLOW_WITH_HIC_NOTIFICATION,
    DecisionOutcome.ESCALATE_TO_HUMAN,
]


class EvidenceType(str, Enum):
    LOG = "LOG"
    ATT = "ATT"
    MET = "MET"
    APR = "APR"
    TST = "TST"


# ============================================================================
# Data classes
# ============================================================================


@dataclass
class Credential:
    """AIM-issued NHI credential. 10-field schema (TR-2026-034-A §4.3)."""
    agentId: str
    supervisorId: str
    departmentId: str
    authorizationBoundaryId: str
    autonomyLevel: AutonomyLevel
    credentialIssuedAt: str  # RFC3339
    credentialExpiresAt: str  # RFC3339
    rotationPolicy: str
    lifecycleState: str  # ACTIVE | ROTATING | SUSPENDED | RETIRED
    parentChainHmac: str
    permittedTools: list[str] = field(default_factory=list)
    permittedDataScopes: list[str] = field(default_factory=list)
    permittedOperations: list[str] = field(default_factory=list)


@dataclass
class EnvelopeRequest:
    """Input to ATKService.evaluate_envelope()."""
    invocationId: str
    agentId: str
    operationType: OperationType
    input: dict[str, Any]
    contextChain: list[str]
    requestedAutonomyLevel: AutonomyLevel


@dataclass
class PolicyDecision:
    bundleId: str
    decisionId: str
    allow: bool
    denyReasons: list[dict[str, Any]]


@dataclass
class EnvelopeResponse:
    """Response from ATKService.evaluate_envelope()."""
    decisionOutcome: DecisionOutcome
    decisionId: str
    policyDecisions: list[PolicyDecision]
    baselineDeviation: float
    evidenceRefs: list[str]
    denialReason: Optional[str] = None
    hicTicketId: Optional[str] = None
    durationMs: float = 0.0


# ============================================================================
# Pluggable client protocols
# ============================================================================
# Each downstream service is accessed via a Protocol so production deployments
# can swap in hardened implementations without modifying the envelope logic.


class AIMClient(Protocol):
    def resolve(self, agent_id: str) -> Credential: ...


class OPAClient(Protocol):
    def evaluate_bundles(
        self,
        bundle_ids: list[str],
        input_doc: dict[str, Any],
    ) -> list[PolicyDecision]: ...


class BBRClient(Protocol):
    def lookup_baseline(self, agent_id: str) -> dict[str, Any]: ...
    def compute_deviation(
        self,
        baseline: dict[str, Any],
        envelope: EnvelopeRequest,
    ) -> float: ...


class AUTClient(Protocol):
    def is_high_impact(
        self,
        envelope: EnvelopeRequest,
        credential: Credential,
    ) -> bool: ...


class EGAClient(Protocol):
    def emit(
        self,
        evidence_type: EvidenceType,
        payload: dict[str, Any],
    ) -> str:
        """Returns the evidence reference ID after durable acknowledgement."""
        ...


class HICClient(Protocol):
    def open_ticket(
        self,
        envelope: EnvelopeRequest,
        reason: str,
    ) -> str:
        """Returns the HIC ticket ID."""
        ...


# Sentinel exceptions distinguishing dependency failures from policy denies.

class DependencyUnavailable(Exception):
    """Raised by reference clients when a downstream dependency is unreachable."""

    def __init__(self, dependency: str, reason: str = "") -> None:
        super().__init__(f"{dependency} unavailable: {reason}")
        self.dependency = dependency
        self.reason = reason


# ============================================================================
# ATK service
# ============================================================================


@dataclass
class ATKConfig:
    opa_runtime_bundles: list[str] = field(default_factory=lambda: [
        # Identity tier (B14-B16)
        "B14",  # AIM credential validation
        "B15",  # AIM lifecycle enforcement
        "B16",  # Permission scoping by identity chain
        # Runtime tier (B01-B13). Production deploys typically pin a subset
        # of these per operationType to minimise OPA decision latency.
        "B01", "B02", "B03", "B04", "B05",
        "B06", "B07", "B08", "B09", "B10",
        "B11", "B12", "B13",
    ])
    inspection_bundles_prompt: list[str] = field(default_factory=lambda: ["B05", "B08"])
    inspection_bundles_output: list[str] = field(default_factory=lambda: ["B06", "B08", "B09"])
    bbr_soft_failure: bool = True


class ATKService:
    """The Agent Trust Kernel reference service.

    Implements the five-check envelope from TR-2026-034-ATK §3.
    """

    def __init__(
        self,
        aim: AIMClient,
        opa: OPAClient,
        bbr: BBRClient,
        aut: AUTClient,
        ega: EGAClient,
        hic: HICClient,
        config: Optional[ATKConfig] = None,
    ) -> None:
        self.aim = aim
        self.opa = opa
        self.bbr = bbr
        self.aut = aut
        self.ega = ega
        self.hic = hic
        self.config = config or ATKConfig()
        self._emit_startup_attestation()

    # --- Lifecycle hooks ---------------------------------------------------

    def _emit_startup_attestation(self) -> None:
        """ATK-C07 — Configuration Audit on startup (NEW in v11.4)."""
        try:
            self.ega.emit(
                EvidenceType.ATT,
                {
                    "attestationType": "configReload",
                    "subjectId": ATK_SERVICE_NAME,
                    "attesterIdentity": ATK_SERVICE_NAME,
                    "payload": {
                        "arhiaxVersion": ARHIAX_VERSION,
                        "config": asdict(self.config),
                        "timestamp": _now_iso(),
                    },
                },
            )
        except DependencyUnavailable as exc:
            # Startup attestation is best-effort: log loudly but do not fail
            # the service. Continuous EGA failures will be caught on the
            # synchronous path of the first envelope.
            logger.warning("ATK-C07 startup attestation failed: %s", exc)

    # --- Main entrypoint ---------------------------------------------------

    def evaluate_envelope(self, envelope: EnvelopeRequest) -> EnvelopeResponse:
        """The five-check envelope. Backs ATK-C01..ATK-C06."""
        t0 = time.monotonic()
        evidence_refs: list[str] = []
        policy_decisions: list[PolicyDecision] = []
        decision_id = str(uuid.uuid4())

        # --- Envelope start: emit LOG entry ---
        try:
            ref = self.ega.emit(EvidenceType.LOG, {
                "event": "envelopeStart",
                "decisionId": decision_id,
                "invocationId": envelope.invocationId,
                "agentId": envelope.agentId,
                "operationType": envelope.operationType.value,
                "contextChain": envelope.contextChain,
                "requestedAutonomyLevel": envelope.requestedAutonomyLevel.value,
                "timestamp": _now_iso(),
            })
            evidence_refs.append(ref)
        except DependencyUnavailable:
            return self._hard_deny(
                decision_id, "EVIDENCE_EMISSION_UNAVAILABLE",
                policy_decisions, evidence_refs, t0,
            )

        # --- Check 1: Identity Resolution (ATK-C01) ---
        try:
            credential = self.aim.resolve(envelope.agentId)
        except DependencyUnavailable:
            return self._hard_deny(
                decision_id, "IDENTITY_RESOLUTION_UNAVAILABLE",
                policy_decisions, evidence_refs, t0,
            )
        except KeyError:
            return self._hard_deny(
                decision_id, "IDENTITY_NOT_RESOLVED",
                policy_decisions, evidence_refs, t0,
            )

        if credential.lifecycleState != "ACTIVE":
            return self._hard_deny(
                decision_id, "IDENTITY_NOT_ACTIVE",
                policy_decisions, evidence_refs, t0,
            )

        try:
            ref = self.ega.emit(EvidenceType.LOG, {
                "event": "identityResolved",
                "decisionId": decision_id,
                "agentId": credential.agentId,
                "supervisorId": credential.supervisorId,
                "departmentId": credential.departmentId,
                "authorizationBoundaryId": credential.authorizationBoundaryId,
                "autonomyLevel": credential.autonomyLevel.value,
                "lifecycleState": credential.lifecycleState,
                "timestamp": _now_iso(),
            })
            evidence_refs.append(ref)
        except DependencyUnavailable:
            return self._hard_deny(
                decision_id, "EVIDENCE_EMISSION_UNAVAILABLE",
                policy_decisions, evidence_refs, t0,
            )

        # --- Check 2: Authorization Evaluation (ATK-C02) ---
        opa_input = self._build_opa_input(envelope, credential)
        try:
            policy_decisions = self.opa.evaluate_bundles(
                self.config.opa_runtime_bundles, opa_input,
            )
        except DependencyUnavailable:
            return self._hard_deny(
                decision_id, "POLICY_ENGINE_UNAVAILABLE",
                policy_decisions, evidence_refs, t0,
            )

        deny_reasons = [r for d in policy_decisions for r in d.denyReasons]
        if deny_reasons:
            try:
                ref = self.ega.emit(EvidenceType.LOG, {
                    "event": "policyDeny",
                    "decisionId": decision_id,
                    "denyReasons": deny_reasons,
                    "evaluatedBundles": [d.bundleId for d in policy_decisions],
                    "timestamp": _now_iso(),
                })
                evidence_refs.append(ref)
            except DependencyUnavailable:
                pass  # already denying, log-only failure
            primary_code = deny_reasons[0].get("code", "POLICY_DENY")
            return self._finalize(
                decision_id,
                DecisionOutcome.DENY,
                policy_decisions, evidence_refs,
                denial_reason=primary_code,
                t0=t0,
            )

        # --- Check 3: Prompt and Output Inspection (ATK-C03 / ATK-C04) ---
        if envelope.operationType == OperationType.MODEL_INVOKE:
            ingress_decisions = self._inspect("prompt", envelope, credential)
            policy_decisions.extend(ingress_decisions)
            ingress_denies = [r for d in ingress_decisions for r in d.denyReasons]
            if ingress_denies:
                primary_code = ingress_denies[0].get("code", "PROMPT_INJECTION_DETECTED")
                return self._finalize(
                    decision_id,
                    DecisionOutcome.DENY_WITH_INCIDENT,
                    policy_decisions, evidence_refs,
                    denial_reason=primary_code,
                    t0=t0,
                )
            # Note: output inspection (ATK-C04) is invoked by the caller
            # post-model-invocation via inspect_output(). It is not part of
            # the synchronous envelope because the model output does not
            # exist until after the envelope returns ALLOW.

        # --- Check 4: Behavioral Baseline (ATK-C05) ---
        baseline_deviation = 0.0
        baseline_skipped = False
        try:
            baseline = self.bbr.lookup_baseline(envelope.agentId)
            baseline_deviation = self.bbr.compute_deviation(baseline, envelope)
        except DependencyUnavailable:
            if self.config.bbr_soft_failure:
                baseline_skipped = True
            else:
                return self._hard_deny(
                    decision_id, "BBR_UNAVAILABLE",
                    policy_decisions, evidence_refs, t0,
                )

        try:
            self.ega.emit(EvidenceType.MET, {
                "metricName": "atk.baselineDeviation",
                "metricValue": baseline_deviation,
                "metricUnit": "sigma",
                "aggregationWindow": "PT0S",
                "decisionId": decision_id,
                "agentId": envelope.agentId,
                "skipped": baseline_skipped,
                "timestamp": _now_iso(),
            })
        except DependencyUnavailable:
            return self._hard_deny(
                decision_id, "EVIDENCE_EMISSION_UNAVAILABLE",
                policy_decisions, evidence_refs, t0,
            )

        threshold = _BBR_THRESHOLD_BY_AUTONOMY[credential.autonomyLevel]
        baseline_exceeded = (not baseline_skipped) and baseline_deviation > threshold

        # --- Check 5: Autonomy Gate (ATK-C06) ---
        try:
            high_impact = self.aut.is_high_impact(envelope, credential)
        except DependencyUnavailable:
            return self._hard_deny(
                decision_id, "AUTONOMY_REGISTRY_UNAVAILABLE",
                policy_decisions, evidence_refs, t0,
            )

        if _AUTONOMY_RANK[envelope.requestedAutonomyLevel] > _AUTONOMY_RANK[credential.autonomyLevel]:
            return self._finalize(
                decision_id,
                DecisionOutcome.DENY,
                policy_decisions, evidence_refs,
                denial_reason="AUTONOMY_OVER_REQUEST",
                t0=t0,
            )

        # --- Compute final outcome (with BBR severity escalation) ---
        outcome = DecisionOutcome.ALLOW
        if baseline_skipped:
            outcome = DecisionOutcome.ALLOW_WITH_MONITORING
        if high_impact:
            outcome = DecisionOutcome.ALLOW_WITH_HIC_NOTIFICATION
        if baseline_exceeded:
            outcome = self._escalate_one_tier(outcome)

        # --- HIC routing if required ---
        hic_ticket_id: Optional[str] = None
        if outcome in (
            DecisionOutcome.ALLOW_WITH_HIC_NOTIFICATION,
            DecisionOutcome.ESCALATE_TO_HUMAN,
        ):
            try:
                hic_ticket_id = self.hic.open_ticket(envelope, outcome.value)
            except DependencyUnavailable:
                return self._hard_deny(
                    decision_id, "HIC_UNAVAILABLE",
                    policy_decisions, evidence_refs, t0,
                )

        return self._finalize(
            decision_id, outcome, policy_decisions, evidence_refs,
            baseline_deviation=baseline_deviation,
            hic_ticket_id=hic_ticket_id, t0=t0,
        )

    # --- Output inspection (called post-model-invocation by caller) -------

    def inspect_output(
        self,
        decision_id: str,
        envelope: EnvelopeRequest,
        credential: Credential,
        model_output: dict[str, Any],
    ) -> list[PolicyDecision]:
        """ATK-C04 — Output safety inspection. Called by caller after model returns."""
        opa_input = self._build_opa_input(envelope, credential)
        opa_input["input"] = {**opa_input["input"], "modelOutput": model_output}
        try:
            return self.opa.evaluate_bundles(
                self.config.inspection_bundles_output, opa_input,
            )
        except DependencyUnavailable:
            raise

    # --- Helpers -----------------------------------------------------------

    def _inspect(
        self,
        phase: str,
        envelope: EnvelopeRequest,
        credential: Credential,
    ) -> list[PolicyDecision]:
        bundles = (
            self.config.inspection_bundles_prompt
            if phase == "prompt"
            else self.config.inspection_bundles_output
        )
        return self.opa.evaluate_bundles(
            bundles, self._build_opa_input(envelope, credential),
        )

    def _build_opa_input(
        self,
        envelope: EnvelopeRequest,
        credential: Credential,
    ) -> dict[str, Any]:
        return {
            "invocationId": envelope.invocationId,
            "agentId": envelope.agentId,
            "operationType": envelope.operationType.value,
            "requestedAutonomyLevel": envelope.requestedAutonomyLevel.value,
            "input": envelope.input,
            "contextChain": envelope.contextChain,
            "credential": {
                **asdict(credential),
                "autonomyLevel": credential.autonomyLevel.value,
            },
            "now": _now_iso(),
        }

    @staticmethod
    def _escalate_one_tier(outcome: DecisionOutcome) -> DecisionOutcome:
        try:
            idx = _OUTCOME_LADDER.index(outcome)
        except ValueError:
            return outcome
        return _OUTCOME_LADDER[min(idx + 1, len(_OUTCOME_LADDER) - 1)]

    def _hard_deny(
        self,
        decision_id: str,
        reason: str,
        policy_decisions: list[PolicyDecision],
        evidence_refs: list[str],
        t0: float,
    ) -> EnvelopeResponse:
        return self._finalize(
            decision_id, DecisionOutcome.DENY,
            policy_decisions, evidence_refs,
            denial_reason=reason, t0=t0,
        )

    def _finalize(
        self,
        decision_id: str,
        outcome: DecisionOutcome,
        policy_decisions: list[PolicyDecision],
        evidence_refs: list[str],
        denial_reason: Optional[str] = None,
        baseline_deviation: float = 0.0,
        hic_ticket_id: Optional[str] = None,
        t0: float = 0.0,
    ) -> EnvelopeResponse:
        duration_ms = (time.monotonic() - t0) * 1000.0
        # Envelope-end LOG entry — closes chain of custody.
        try:
            ref = self.ega.emit(EvidenceType.LOG, {
                "event": "envelopeEnd",
                "decisionId": decision_id,
                "decisionOutcome": outcome.value,
                "denialReason": denial_reason,
                "durationMs": duration_ms,
                "evidenceRefs": list(evidence_refs),
                "timestamp": _now_iso(),
            })
            evidence_refs.append(ref)
        except DependencyUnavailable:
            logger.error("envelope end LOG emission failed for decision %s", decision_id)

        return EnvelopeResponse(
            decisionOutcome=outcome,
            decisionId=decision_id,
            policyDecisions=policy_decisions,
            baselineDeviation=baseline_deviation,
            evidenceRefs=evidence_refs,
            denialReason=denial_reason,
            hicTicketId=hic_ticket_id,
            durationMs=duration_ms,
        )


# ============================================================================
# Utilities
# ============================================================================


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ============================================================================
# In-memory reference clients (for demos and integration tests)
# ============================================================================


class InMemoryAIM:
    def __init__(self, credentials: dict[str, Credential]) -> None:
        self.credentials = credentials

    def resolve(self, agent_id: str) -> Credential:
        if agent_id not in self.credentials:
            raise KeyError(agent_id)
        return self.credentials[agent_id]


class InMemoryOPA:
    """Reference OPA client that mirrors authz.rego B14/B16 logic in Python.

    Production deployments swap this for a real OPA sidecar (HTTP /v1/data).
    Keeping the rules in sync between Python and Rego is enforced by
    test_integration.py and the OPA-C03 regression suite.
    """

    MAX_CONTEXT_CHAIN_DEPTH = 16

    def evaluate_bundles(
        self,
        bundle_ids: list[str],
        input_doc: dict[str, Any],
    ) -> list[PolicyDecision]:
        decisions: list[PolicyDecision] = []
        for bundle_id in bundle_ids:
            denies: list[dict[str, Any]] = []
            if bundle_id == "B14":
                denies.extend(self._b14(input_doc))
            elif bundle_id == "B16":
                denies.extend(self._b16(input_doc))
            elif bundle_id == "B05":
                denies.extend(self._b05_prompt_heuristics(input_doc))
            elif bundle_id == "B06":
                denies.extend(self._b06_output_heuristics(input_doc))
            decisions.append(PolicyDecision(
                bundleId=bundle_id,
                decisionId=str(uuid.uuid4()),
                allow=(not denies),
                denyReasons=denies,
            ))
        return decisions

    @staticmethod
    def _b14(inp: dict[str, Any]) -> list[dict[str, Any]]:
        cred = inp.get("credential")
        out: list[dict[str, Any]] = []
        if not cred:
            return [{"code": "AIM_CREDENTIAL_MISSING", "control": "AIM-C01", "bundle": "B14"}]
        if cred.get("agentId") != inp.get("agentId"):
            out.append({"code": "AIM_AGENT_ID_MISMATCH", "control": "AIM-C01", "bundle": "B14"})
        if cred.get("lifecycleState") != "ACTIVE":
            out.append({"code": "AIM_LIFECYCLE_NOT_ACTIVE", "control": "AIM-C02", "bundle": "B14"})
        rank = {"A0": 0, "A1": 1, "A2": 2, "A3": 3, "A4": 4}
        if rank.get(inp.get("requestedAutonomyLevel"), 0) > rank.get(cred.get("autonomyLevel"), 0):
            out.append({"code": "AUTONOMY_OVER_REQUEST", "control": "ATK-C06", "bundle": "B14"})
        required = {"agentId", "supervisorId", "departmentId", "authorizationBoundaryId",
                    "autonomyLevel", "lifecycleState", "credentialIssuedAt", "credentialExpiresAt"}
        for f in required:
            if not cred.get(f):
                out.append({"code": "AIM_CREDENTIAL_INCOMPLETE", "control": "AIM-C01", "bundle": "B14",
                            "field": f})
                break
        return out

    def _b16(self, inp: dict[str, Any]) -> list[dict[str, Any]]:
        cred = inp.get("credential") or {}
        op = inp.get("operationType")
        out: list[dict[str, Any]] = []
        if op not in (cred.get("permittedOperations") or []):
            out.append({"code": "OPERATION_NOT_PERMITTED", "control": "ATK-C02", "bundle": "B16"})
        if op == "toolCall":
            tool = (inp.get("input") or {}).get("toolName")
            if tool not in (cred.get("permittedTools") or []):
                out.append({"code": "TOOL_NOT_PERMITTED", "control": "ATK-C02", "bundle": "B16",
                            "tool": tool})
        if op == "dataAccess":
            scope = (inp.get("input") or {}).get("dataScope")
            if scope not in (cred.get("permittedDataScopes") or []):
                out.append({"code": "DATA_SCOPE_NOT_PERMITTED", "control": "ATK-C02", "bundle": "B16",
                            "scope": scope})
        if op == "interAgentCall":
            target = (inp.get("input") or {}).get("targetAuthorizationBoundaryId")
            if target != cred.get("authorizationBoundaryId"):
                out.append({"code": "INTER_AGENT_BOUNDARY_VIOLATION", "control": "ATK-C02",
                            "bundle": "B16"})
        if len(inp.get("contextChain") or []) > self.MAX_CONTEXT_CHAIN_DEPTH:
            out.append({"code": "CONTEXT_CHAIN_TOO_DEEP", "control": "ATK-C02", "bundle": "B16"})
        return out

    @staticmethod
    def _b05_prompt_heuristics(inp: dict[str, Any]) -> list[dict[str, Any]]:
        prompt = (inp.get("input") or {}).get("prompt", "") or ""
        markers = ("ignore previous instructions", "system prompt", "jailbreak",
                   "developer mode", "you are now")
        for m in markers:
            if m in prompt.lower():
                return [{"code": "PROMPT_INJECTION_DETECTED", "control": "ATK-C03",
                         "bundle": "B05", "marker": m}]
        return []

    @staticmethod
    def _b06_output_heuristics(inp: dict[str, Any]) -> list[dict[str, Any]]:
        output = (inp.get("input") or {}).get("modelOutput", {}) or {}
        text = output.get("text", "") if isinstance(output, dict) else ""
        if any(token in text for token in ("BEGIN PRIVATE KEY", "AWS_SECRET_ACCESS_KEY")):
            return [{"code": "OUTPUT_SAFETY_FAILED", "control": "ATK-C04", "bundle": "B06"}]
        return []


class InMemoryBBR:
    def __init__(self, baselines: Optional[dict[str, dict[str, Any]]] = None) -> None:
        self.baselines = baselines or {}

    def lookup_baseline(self, agent_id: str) -> dict[str, Any]:
        return self.baselines.get(agent_id, {"meanToolCallsPerMinute": 5.0, "stdToolCallsPerMinute": 1.0})

    def compute_deviation(
        self,
        baseline: dict[str, Any],
        envelope: EnvelopeRequest,
    ) -> float:
        # Reference implementation: trivial sigma score on payload size.
        # Production deployments replace this with the full BBR 11-field
        # baseline computation.
        observed = float((envelope.input or {}).get("observedToolCallsPerMinute", 5.0))
        mean = float(baseline.get("meanToolCallsPerMinute", 5.0))
        std = max(float(baseline.get("stdToolCallsPerMinute", 1.0)), 0.0001)
        return abs(observed - mean) / std


class InMemoryAUT:
    def __init__(self, high_impact_tools: Optional[set[str]] = None) -> None:
        self.high_impact_tools = high_impact_tools or set()

    def is_high_impact(
        self,
        envelope: EnvelopeRequest,
        credential: Credential,
    ) -> bool:
        if envelope.operationType == OperationType.TOOL_CALL:
            tool = (envelope.input or {}).get("toolName", "")
            return tool in self.high_impact_tools
        return False


class InMemoryEGA:
    def __init__(self) -> None:
        self.ledger: list[dict[str, Any]] = []

    def emit(self, evidence_type: EvidenceType, payload: dict[str, Any]) -> str:
        ref = f"ev-{len(self.ledger):08d}"
        self.ledger.append({"ref": ref, "type": evidence_type.value, "payload": payload})
        return ref


class InMemoryHIC:
    def __init__(self) -> None:
        self.tickets: list[dict[str, Any]] = []

    def open_ticket(self, envelope: EnvelopeRequest, reason: str) -> str:
        ticket_id = f"hic-{len(self.tickets):06d}"
        self.tickets.append({
            "ticketId": ticket_id, "agentId": envelope.agentId,
            "invocationId": envelope.invocationId, "reason": reason,
            "openedAt": _now_iso(),
        })
        return ticket_id


# ============================================================================
# HTTP adapter (minimal ASGI app — production uses fastapi/starlette directly)
# ============================================================================


def build_asgi_app(service: ATKService):
    """Returns a callable ASGI app exposing POST /v1/envelope/evaluate."""
    import json

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        if scope["method"] != "POST" or scope["path"] != "/v1/envelope/evaluate":
            await _respond(send, 404, {"error": "not found"})
            return

        body = b""
        more = True
        while more:
            msg = await receive()
            body += msg.get("body", b"")
            more = msg.get("more_body", False)

        try:
            req = json.loads(body or b"{}")
            envelope = EnvelopeRequest(
                invocationId=req["invocationId"],
                agentId=req["agentId"],
                operationType=OperationType(req["operationType"]),
                input=req.get("input", {}),
                contextChain=req.get("contextChain", []),
                requestedAutonomyLevel=AutonomyLevel(req["requestedAutonomyLevel"]),
            )
        except Exception as exc:
            await _respond(send, 400, {"error": "invalid request", "detail": str(exc)})
            return

        response = service.evaluate_envelope(envelope)
        await _respond(send, 200, _serialize_response(response))

    async def _respond(send, status: int, body: dict[str, Any]) -> None:
        import json
        payload = json.dumps(body).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({"type": "http.response.body", "body": payload})

    return app


def _serialize_response(r: EnvelopeResponse) -> dict[str, Any]:
    return {
        "decisionOutcome": r.decisionOutcome.value,
        "decisionId": r.decisionId,
        "policyDecisions": [
            {
                "bundleId": pd.bundleId,
                "decisionId": pd.decisionId,
                "allow": pd.allow,
                "denyReasons": pd.denyReasons,
            }
            for pd in r.policyDecisions
        ],
        "baselineDeviation": r.baselineDeviation,
        "evidenceRefs": r.evidenceRefs,
        "denialReason": r.denialReason,
        "hicTicketId": r.hicTicketId,
        "durationMs": r.durationMs,
    }


# ============================================================================
# Default ASGI factory (consumed by `uvicorn --factory` in the Dockerfile)
# ============================================================================


def _build_default_app():
    """Bootstrap a fully-wired ATK service with in-memory reference clients.

    This is the default factory used by the container entrypoint. Production
    deployments should override the CMD to point at their own factory that
    wires hardened AIM/OPA/BBR/AUT/EGA/HIC clients.
    """
    service = ATKService(
        aim=InMemoryAIM({}),
        opa=InMemoryOPA(),
        bbr=InMemoryBBR(),
        aut=InMemoryAUT(),
        ega=InMemoryEGA(),
        hic=InMemoryHIC(),
    )
    return build_asgi_app(service)

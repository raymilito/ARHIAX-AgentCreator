"""
ARHIA v11.5 — C09 Reference Implementation (Phase 1)
Module: gate.py — Divergence Gate (INT-C02)

Python port of interp.rego v0.1 for the reference implementation.
Production deployments would call OPA directly; this port exists so the
test harness can run without an OPA binary.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from arhia_c09.cir import CIR
from arhia_c09.envelope import Envelope


GateOutcome = Literal["force_hil", "weighted", "log_only", "no_signal"]


@dataclass
class GateConfig:
    tau_div_general: float = 0.65
    tau_div_regulated: float = 0.40
    max_signal_age_sec: int = 300
    min_impact_class_for_gate: int = 3
    fail_closed_on_missing_signal: bool = False
    regulated_sectors: frozenset[str] = frozenset(
        {"health", "finance", "critical_infrastructure"}
    )


@dataclass
class GateDecision:
    outcome: GateOutcome
    tau_div_applied: float
    signal_admissible: bool
    inadmissibility_reasons: list[str]
    divergence_triggered: bool
    divergence_lower_bound: float | None
    reason: str
    policy_version: str = "interp.rego/0.1 (py-port)"


class DivergenceGate:
    """Implements INT-C02 enforcement against an INTERP-EV envelope."""

    def __init__(self, cir: CIR, config: GateConfig | None = None) -> None:
        self.cir = cir
        self.config = config or GateConfig()

    def _tau_div(self, sector: str | None) -> float:
        if sector and sector in self.config.regulated_sectors:
            return self.config.tau_div_regulated
        return self.config.tau_div_general

    def _admissibility(
        self, env: Envelope, now: datetime
    ) -> tuple[bool, list[str]]:
        reasons: list[str] = []

        producer = self.cir.get(env.producer)
        if producer is None or not producer.is_active(now):
            reasons.append("producer_not_accredited")
        elif not producer.is_calibration_fresh(now):
            reasons.append("calibration_expired")

        produced = datetime.fromisoformat(env.produced_at.replace("Z", "+00:00"))
        if (now - produced) > timedelta(seconds=self.config.max_signal_age_sec):
            reasons.append("signal_stale")

        if producer is not None:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            try:
                pubkey = Ed25519PublicKey.from_public_bytes(producer.public_key)
                if not env.verify(pubkey):
                    reasons.append("signature_invalid")
            except Exception:
                reasons.append("signature_invalid")
        else:
            reasons.append("signature_invalid")

        return (len(reasons) == 0, reasons)

    def evaluate(
        self,
        envelope: Envelope | None,
        action_impact_class: int,
        deployment_sector: str | None,
        now: datetime,
    ) -> GateDecision:
        tau = self._tau_div(deployment_sector)

        if envelope is None:
            outcome: GateOutcome = (
                "force_hil"
                if (
                    self.config.fail_closed_on_missing_signal
                    and action_impact_class >= 4
                    and deployment_sector in self.config.regulated_sectors
                )
                else "no_signal"
            )
            return GateDecision(
                outcome=outcome,
                tau_div_applied=tau,
                signal_admissible=False,
                inadmissibility_reasons=["no_envelope_present"],
                divergence_triggered=False,
                divergence_lower_bound=None,
                reason=("fail_closed_on_missing_signal active"
                        if outcome == "force_hil"
                        else "no interpretability signal available"),
            )

        admissible, reasons = self._admissibility(envelope, now)

        if not admissible:
            return GateDecision(
                outcome="log_only",
                tau_div_applied=tau,
                signal_admissible=False,
                inadmissibility_reasons=reasons,
                divergence_triggered=False,
                divergence_lower_bound=None,
                reason=f"signal inadmissible: {','.join(reasons)}",
            )

        # Class C divergence rule
        lb: float | None = None
        if envelope.klass == "C":
            for c in envelope.concepts:
                if c.name == "behavioral_divergence":
                    lb = c.ci_95[0]
                    break

        if (
            lb is not None
            and lb > tau
            and action_impact_class >= self.config.min_impact_class_for_gate
        ):
            return GateDecision(
                outcome="force_hil",
                tau_div_applied=tau,
                signal_admissible=True,
                inadmissibility_reasons=[],
                divergence_triggered=True,
                divergence_lower_bound=lb,
                reason=(f"INT-C02 divergence gate: lower_bound={lb:.3f} > "
                        f"tau_div={tau:.2f}, impact_class={action_impact_class}"),
            )

        if envelope.klass == "A":
            return GateDecision(
                outcome="weighted",
                tau_div_applied=tau,
                signal_admissible=True,
                inadmissibility_reasons=[],
                divergence_triggered=False,
                divergence_lower_bound=lb,
                reason="Class A enrichment contributed to ATK aggregator",
            )

        return GateDecision(
            outcome="weighted",
            tau_div_applied=tau,
            signal_admissible=True,
            inadmissibility_reasons=[],
            divergence_triggered=False,
            divergence_lower_bound=lb,
            reason=("Class C signal admissible but below threshold or "
                    "impact class too low"),
        )

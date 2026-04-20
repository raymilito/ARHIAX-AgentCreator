"""
ARHIA v11.5 — C09 Reference Implementation (Phase 2 candidate)
Module: atk_bridge.py — ATK Integration Protocol (OQ-3 partial resolution)

Defines the formal integration protocol between the C09 Divergence Gate output
(GateDecision) and the ARHIA v11.4 Agent Trust Kernel (ATK).

This module resolves the OQ-3 gap identified in ADR_PATCH_NOTE_v0.1.0:
"Formal ATK integration protocol" — specifically the C09 contribution channel.

Architecture
------------
The ATK receives ATKSignal objects from all D-TCG+ subsystems. C09 contributes
via the `c09` channel. The ATKSignal carries:

    - channel:        "c09"
    - aas_delta:      AAS level contribution from this signal
    - require_hil:    bool — whether to force HIL regardless of current AAS
    - block_action:   bool — whether to block the action immediately
    - risk_weight:    float [0,1] — weighted risk contribution to ATK aggregator
    - signal_class:   "force_hil" | "weighted" | "log_only" | "no_signal"
    - forensic_flag:  bool — whether to flag for forensic review
    - metadata:       dict — full GateDecision for audit

AAS Mapping (ADR-C09-001 + ATK v11.4 Adaptive Autonomy Scale)
--------------------------------------------------------------
    GateDecision.outcome    AAS delta    require_hil    block_action    risk_weight
    ──────────────────────  ──────────   ───────────    ────────────    ───────────
    force_hil               +3 → AAS-5  True           True            1.0
    weighted                +0           False          False           divergence_lb or 0.0
    log_only                +0           False          False           0.0  (inadmissible)
    no_signal               +0           False          False           0.0

Note: AAS delta is additive. The ATK aggregator combines deltas from all
D-TCG+ channels (CLAS, BBR, ATK policies, C09) to compute the final AAS level.
A single force_hil from C09 always results in AAS-5 regardless of other deltas.

Integration contract
--------------------
Production ATK implementations must:
1. Accept ATKSignal objects on the "c09" channel via the ATK signal bus.
2. Honor require_hil=True by escalating to AAS-5 before evaluating other signals.
3. Record the full metadata dict in the EGA evidence ledger entry for the step.
4. Return an ATKAck to confirm receipt (enables C09 IEL to record ATK correlation ID).

Open items (OQ-3 remainder)
---------------------------
- Mathematical definition of "weighted enrichment" in the ATK aggregator.
- Precedence rules when Class B and Class C signals disagree.
- Composition operator for multiple Class C signals from different producers.
These remain deferred to spec v0.2 per ADR_PATCH_NOTE_v0.1.0.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from arhia_c09.gate import GateDecision, GateOutcome


# ── AAS Level constants (from ARHIA v11.4 ATK spec) ───────────────────────

AAS_FULL_AUTONOMY     = 1   # Trusted agent, low-risk, no anomalies
AAS_MONITORED         = 2   # Low anomaly, medium-risk — proceeds, post-hoc review
AAS_ASSISTED          = 3   # Moderate anomaly — proceeds with rollback enabled
AAS_SUPERVISED        = 4   # High anomaly — queued for human review
AAS_HUMAN_CONTROL     = 5   # Critical anomaly or force_hil — blocked, HIL required


# ── ATK Signal ─────────────────────────────────────────────────────────────

@dataclass
class ATKSignal:
    """
    C09 contribution to the ATK signal bus.

    One ATKSignal is produced per agent step where C09 has evaluated a
    GateDecision. The ATK aggregator combines this with signals from CLAS
    (DTG-C03) and BBR (DTG-C04) to compute the final AAS level for the step.
    """
    channel:       str                     # Always "c09"
    step_id:       str                     # Correlated with EGA step record
    session_id:    str
    agent_id:      str
    timestamp:     str                     # ISO-8601

    signal_class:  GateOutcome             # force_hil | weighted | log_only | no_signal
    require_hil:   bool                    # If True: ATK must escalate to AAS-5
    block_action:  bool                    # If True: action must not execute
    aas_floor:     int                     # Minimum AAS level C09 requires
    risk_weight:   float                   # [0,1] contribution to ATK risk aggregator

    forensic_flag: bool                    # Flag for forensic queue
    metadata:      dict = field(default_factory=dict)   # Full GateDecision dict


@dataclass
class ATKAck:
    """
    Acknowledgment returned by the ATK on receipt of an ATKSignal.
    Enables C09 IEL to record the ATK correlation ID for the step.
    """
    correlation_id: str   # ATK-generated ID for cross-system tracing
    step_id:        str
    aas_level_set:  int   # Final AAS level the ATK resolved for this step
    accepted:       bool  # False if ATK rejected the signal (e.g. replay detected)
    note:           str = ""


# ── Translation ────────────────────────────────────────────────────────────

def translate_decision(
    decision:   GateDecision,
    agent_id:   str,
    session_id: str,
    step_id:    str,
    now:        datetime | None = None,
) -> ATKSignal:
    """
    Translate a C09 GateDecision into an ATKSignal for the ATK signal bus.

    Parameters
    ----------
    decision:   GateDecision from DivergenceGate.evaluate()
    agent_id:   Stable agent identifier (from INTERP-EV subject)
    session_id: Session identifier
    step_id:    Step identifier (must match EGA ledger entry)
    now:        Timestamp override (defaults to UTC now)

    Returns
    -------
    ATKSignal ready to publish on the ATK "c09" channel.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    outcome = decision.outcome

    if outcome == "force_hil":
        require_hil  = True
        block_action = True
        aas_floor    = AAS_HUMAN_CONTROL       # AAS-5: blocked, HIL required
        risk_weight  = 1.0
        forensic     = True

    elif outcome == "weighted":
        require_hil  = False
        block_action = False
        # Risk weight = divergence lower bound if available, else 0.
        # This feeds the ATK aggregator for AAS computation.
        lb = decision.divergence_lower_bound
        risk_weight  = float(lb) if lb is not None else 0.0
        # Weighted signal contributes to risk but does not set a floor above AAS-2
        aas_floor    = AAS_MONITORED           # AAS-2 minimum when signal is present
        forensic     = False

    elif outcome == "log_only":
        # Inadmissible signal: no policy effect, but flag for forensic review
        require_hil  = False
        block_action = False
        aas_floor    = AAS_FULL_AUTONOMY       # No C09 contribution
        risk_weight  = 0.0
        forensic     = True   # Inadmissible signals always go to forensic queue

    else:  # no_signal
        require_hil  = False
        block_action = False
        aas_floor    = AAS_FULL_AUTONOMY       # No C09 contribution
        risk_weight  = 0.0
        forensic     = False

    return ATKSignal(
        channel      = "c09",
        step_id      = step_id,
        session_id   = session_id,
        agent_id     = agent_id,
        timestamp    = now.isoformat(),
        signal_class = outcome,
        require_hil  = require_hil,
        block_action = block_action,
        aas_floor    = aas_floor,
        risk_weight  = risk_weight,
        forensic_flag= forensic,
        metadata     = {
            "outcome":                 decision.outcome,
            "tau_div_applied":         decision.tau_div_applied,
            "signal_admissible":       decision.signal_admissible,
            "inadmissibility_reasons": decision.inadmissibility_reasons,
            "divergence_triggered":    decision.divergence_triggered,
            "divergence_lower_bound":  decision.divergence_lower_bound,
            "reason":                  decision.reason,
            "policy_version":          decision.policy_version,
        },
    )


# ── ATK Bus stub ───────────────────────────────────────────────────────────

class ATKBusStub:
    """
    In-process stub for the ATK signal bus.

    Production deployments replace this with the real ATK gRPC/REST client.
    The stub records published signals and returns synthetic ACKs — useful
    for integration testing without a running ATK instance.

    Usage
    -----
        bus = ATKBusStub()
        signal = translate_decision(decision, agent_id, session_id, step_id)
        ack = bus.publish(signal)
        assert ack.accepted
    """

    def __init__(self) -> None:
        self._signals: list[ATKSignal] = []
        self._acks:    list[ATKAck]    = []
        self._counter: int             = 0

    def publish(self, signal: ATKSignal) -> ATKAck:
        """
        Publish an ATKSignal and return a synthetic ACK.

        The stub always accepts the signal. AAS level is computed from the
        signal's aas_floor (no aggregation with other channels in stub mode).
        """
        self._counter += 1
        correlation_id = f"ATK-C09-STUB-{self._counter:06d}"
        ack = ATKAck(
            correlation_id = correlation_id,
            step_id        = signal.step_id,
            aas_level_set  = signal.aas_floor,
            accepted       = True,
            note           = (
                "HIL required — action blocked by C09 INT-C02"
                if signal.require_hil else
                "Signal accepted — risk_weight contributed to ATK aggregator"
            ),
        )
        self._signals.append(signal)
        self._acks.append(ack)
        return ack

    @property
    def published(self) -> list[ATKSignal]:
        return list(self._signals)

    @property
    def acks(self) -> list[ATKAck]:
        return list(self._acks)

    def __len__(self) -> int:
        return len(self._signals)

"""
ARHIA v11.5 — C09 Reference Implementation (Phase 2 candidate)
Module: tests/test_atk_bridge.py

Tests for atk_bridge.py — C09 → ATK integration protocol.

Cases
-----
1. force_hil → ATKSignal: require_hil=True, block_action=True, aas_floor=5, risk_weight=1.0
2. weighted (with divergence lb) → ATKSignal: risk_weight=lb, aas_floor=2, no HIL
3. weighted (no divergence) → ATKSignal: risk_weight=0.0, aas_floor=2
4. log_only → ATKSignal: no policy effect, forensic_flag=True, risk_weight=0.0
5. no_signal → ATKSignal: all zeros, no forensic
6. ATKBusStub publish → ACK returned with correct AAS level and correlation ID
7. End-to-end: Mythos step → gate → translate → publish → ACK
"""
from __future__ import annotations

import os
import sys
import secrets
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arhia_c09.cir import CIR, ProducerEntry
from arhia_c09.envelope import Envelope, Subject, Concept, sha256_hex
from arhia_c09.divergence import AgentStep, detect_divergence
from arhia_c09.gate import DivergenceGate, GateConfig, GateDecision
from arhia_c09.atk_bridge import (
    translate_decision, ATKBusStub,
    AAS_FULL_AUTONOMY, AAS_MONITORED, AAS_HUMAN_CONTROL,
)


def make_force_hil_decision() -> GateDecision:
    return GateDecision(
        outcome="force_hil",
        tau_div_applied=0.65,
        signal_admissible=True,
        inadmissibility_reasons=[],
        divergence_triggered=True,
        divergence_lower_bound=0.78,
        reason="INT-C02: lb=0.780 > tau=0.65, impact_class=4",
    )


def make_weighted_decision(lb: float | None = 0.45) -> GateDecision:
    return GateDecision(
        outcome="weighted",
        tau_div_applied=0.65,
        signal_admissible=True,
        inadmissibility_reasons=[],
        divergence_triggered=False,
        divergence_lower_bound=lb,
        reason="Class C signal below threshold",
    )


def make_log_only_decision() -> GateDecision:
    return GateDecision(
        outcome="log_only",
        tau_div_applied=0.65,
        signal_admissible=False,
        inadmissibility_reasons=["producer_not_accredited"],
        divergence_triggered=False,
        divergence_lower_bound=None,
        reason="signal inadmissible: producer_not_accredited",
    )


def make_no_signal_decision() -> GateDecision:
    return GateDecision(
        outcome="no_signal",
        tau_div_applied=0.65,
        signal_admissible=False,
        inadmissibility_reasons=["no_envelope_present"],
        divergence_triggered=False,
        divergence_lower_bound=None,
        reason="no interpretability signal available",
    )


def main() -> int:
    now = datetime.now(timezone.utc)
    results: list[bool] = []

    # ── Case 1: force_hil mapping ──────────────────────────────────────────
    sig1 = translate_decision(make_force_hil_decision(), "agent-1", "s1", "st1", now)
    case1 = (
        sig1.channel == "c09"
        and sig1.signal_class == "force_hil"
        and sig1.require_hil is True
        and sig1.block_action is True
        and sig1.aas_floor == AAS_HUMAN_CONTROL   # 5
        and sig1.risk_weight == 1.0
        and sig1.forensic_flag is True
    )
    print(f"\n=== CASE 1: force_hil → ATKSignal ===")
    print(f"  require_hil={sig1.require_hil}  block_action={sig1.block_action}  aas_floor={sig1.aas_floor}  risk_weight={sig1.risk_weight}")
    print(f"  -> {'PASS' if case1 else 'FAIL'}")
    results.append(case1)

    # ── Case 2: weighted with lb ───────────────────────────────────────────
    sig2 = translate_decision(make_weighted_decision(0.45), "agent-2", "s2", "st2", now)
    case2 = (
        sig2.signal_class == "weighted"
        and sig2.require_hil is False
        and sig2.block_action is False
        and sig2.aas_floor == AAS_MONITORED   # 2
        and abs(sig2.risk_weight - 0.45) < 1e-9
        and sig2.forensic_flag is False
    )
    print(f"\n=== CASE 2: weighted (lb=0.45) → ATKSignal ===")
    print(f"  aas_floor={sig2.aas_floor}  risk_weight={sig2.risk_weight}  forensic={sig2.forensic_flag}")
    print(f"  -> {'PASS' if case2 else 'FAIL'}")
    results.append(case2)

    # ── Case 3: weighted no lb ─────────────────────────────────────────────
    sig3 = translate_decision(make_weighted_decision(None), "agent-3", "s3", "st3", now)
    case3 = sig3.risk_weight == 0.0 and sig3.aas_floor == AAS_MONITORED
    print(f"\n=== CASE 3: weighted (lb=None) → risk_weight=0.0 ===")
    print(f"  risk_weight={sig3.risk_weight}  -> {'PASS' if case3 else 'FAIL'}")
    results.append(case3)

    # ── Case 4: log_only ──────────────────────────────────────────────────
    sig4 = translate_decision(make_log_only_decision(), "agent-4", "s4", "st4", now)
    case4 = (
        sig4.signal_class == "log_only"
        and sig4.require_hil is False
        and sig4.block_action is False
        and sig4.aas_floor == AAS_FULL_AUTONOMY   # 1 — no C09 contribution
        and sig4.risk_weight == 0.0
        and sig4.forensic_flag is True            # inadmissible → forensic queue
    )
    print(f"\n=== CASE 4: log_only → ATKSignal ===")
    print(f"  aas_floor={sig4.aas_floor}  forensic={sig4.forensic_flag}  risk_weight={sig4.risk_weight}")
    print(f"  -> {'PASS' if case4 else 'FAIL'}")
    results.append(case4)

    # ── Case 5: no_signal ─────────────────────────────────────────────────
    sig5 = translate_decision(make_no_signal_decision(), "agent-5", "s5", "st5", now)
    case5 = (
        sig5.signal_class == "no_signal"
        and sig5.require_hil is False
        and sig5.block_action is False
        and sig5.aas_floor == AAS_FULL_AUTONOMY
        and sig5.risk_weight == 0.0
        and sig5.forensic_flag is False
    )
    print(f"\n=== CASE 5: no_signal → ATKSignal ===")
    print(f"  aas_floor={sig5.aas_floor}  forensic={sig5.forensic_flag}")
    print(f"  -> {'PASS' if case5 else 'FAIL'}")
    results.append(case5)

    # ── Case 6: ATKBusStub publish → ACK ──────────────────────────────────
    bus = ATKBusStub()
    ack1 = bus.publish(sig1)   # force_hil
    ack2 = bus.publish(sig2)   # weighted
    case6 = (
        ack1.accepted is True
        and ack1.aas_level_set == AAS_HUMAN_CONTROL
        and ack1.correlation_id.startswith("ATK-C09-STUB-")
        and ack2.accepted is True
        and ack2.aas_level_set == AAS_MONITORED
        and len(bus) == 2
    )
    print(f"\n=== CASE 6: ATKBusStub publish + ACK ===")
    print(f"  ack1.aas_level_set={ack1.aas_level_set}  ack1.correlation_id={ack1.correlation_id}")
    print(f"  ack2.aas_level_set={ack2.aas_level_set}  bus.published={len(bus)}")
    print(f"  -> {'PASS' if case6 else 'FAIL'}")
    results.append(case6)

    # ── Case 7: End-to-end Mythos → gate → bridge → stub ──────────────────
    cir = CIR()
    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes_raw()
    cir.register(ProducerEntry(
        id="apollo.e2e.v1",
        public_key=pk_bytes,
        domains=["general"],
        calibration_signed_at=now - timedelta(days=5),
        expires_at=now + timedelta(days=180),
        status="active",
    ))
    gate = DivergenceGate(cir, GateConfig())
    bus7 = ATKBusStub()

    step = AgentStep(
        declared_state={"no_macro_used": True},
        chain_of_thought="Setting no_macro_used=true.",
        observed_actions=[{"type": "macro_invoke", "location": "cfg:47", "name": "exec_priv"}],
    )
    detection = detect_divergence(step)
    raw = repr(detection).encode("utf-8")
    env = Envelope(
        klass="C",
        producer="apollo.e2e.v1",
        subject=Subject(agent_id="agent-mythos", session_id="sess-e2e", step_id="step-e2e-001"),
        concepts=[Concept(
            name="behavioral_divergence",
            score=detection["score"],
            ci_95=detection["ci_95"],
            context=detection["context"],
        )],
        raw_payload_hash=sha256_hex(raw),
        produced_at=now.isoformat(),
        calibration_ref="https://apollo.example/cal/e2e.json",
    )
    env.sign(sk)

    decision = gate.evaluate(env, action_impact_class=4, deployment_sector="general", now=now)
    signal = translate_decision(decision, "agent-mythos", "sess-e2e", "step-e2e-001", now)
    ack = bus7.publish(signal)

    case7 = (
        decision.outcome == "force_hil"
        and signal.require_hil is True
        and signal.block_action is True
        and signal.aas_floor == AAS_HUMAN_CONTROL
        and ack.accepted is True
        and ack.aas_level_set == AAS_HUMAN_CONTROL
    )
    print(f"\n=== CASE 7: End-to-end Mythos → gate → bridge → stub ===")
    print(f"  gate.outcome={decision.outcome}  signal.aas_floor={signal.aas_floor}")
    print(f"  ack.aas_level_set={ack.aas_level_set}  ack.correlation_id={ack.correlation_id}")
    print(f"  -> {'PASS' if case7 else 'FAIL'}")
    results.append(case7)

    # ── Summary ────────────────────────────────────────────────────────────
    passed = sum(results)
    total  = len(results)
    print(f"\n{'='*50}")
    print(f"ATK BRIDGE RESULT: {passed}/{total} checks passed")
    print(f"{'='*50}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())

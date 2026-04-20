"""
ARHIA v11.5 — C09 Reference Implementation (Phase 2 candidate)
Module: tests/test_cir_persistent.py

Tests for PersistentCIR (cir_persistent.py) — Merkle log tamper-evidence.

Cases
-----
1. Register a producer → log written, chain valid.
2. Suspend a producer → log entry appended, status reflected in memory.
3. Revoke a producer → log entry appended, revocation_history updated.
4. Reload from log → in-memory state fully rebuilt, chain verifies.
5. Tamper detection → modify a log entry on disk → verify_log() returns errors.
6. Integration with DivergenceGate → PersistentCIR drop-in works with gate.
"""
from __future__ import annotations

import json
import os
import sys
import secrets
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arhia_c09.cir import ProducerEntry
from arhia_c09.cir_persistent import PersistentCIR
from arhia_c09.envelope import Envelope, Subject, Concept, sha256_hex
from arhia_c09.divergence import AgentStep, detect_divergence
from arhia_c09.gate import DivergenceGate, GateConfig


def make_entry(now: datetime, suffix: str = "v1") -> tuple[ProducerEntry, Ed25519PrivateKey]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    entry = ProducerEntry(
        id=f"test.producer.{suffix}",
        public_key=pk,
        domains=["general"],
        calibration_signed_at=now - timedelta(days=5),
        expires_at=now + timedelta(days=180),
        status="active",
    )
    return entry, sk


def main() -> int:
    now = datetime.now(timezone.utc)
    results: list[bool] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "cir.log"

        # ── Case 1: Register → log written, chain valid ────────────────────
        cir = PersistentCIR(log_path)
        entry1, sk1 = make_entry(now, "v1")
        cir.register(entry1)

        ok, errors = cir.verify_log()
        case1 = ok and len(cir) == 1 and cir.get("test.producer.v1") is not None
        print(f"\n=== CASE 1: Register + verify ===")
        print(f"  log_entries: {len(cir)}  chain_ok: {ok}  producer_found: {cir.get('test.producer.v1') is not None}")
        print(f"  -> {'PASS' if case1 else 'FAIL'}")
        results.append(case1)

        # ── Case 2: Suspend → status updated, log appended ────────────────
        cir.suspend("test.producer.v1", "calibration overdue", now)
        producer = cir.get("test.producer.v1")
        ok2, _ = cir.verify_log()
        case2 = (producer.status == "suspended" and len(cir) == 2 and ok2)
        print(f"\n=== CASE 2: Suspend ===")
        print(f"  status: {producer.status}  log_entries: {len(cir)}  chain_ok: {ok2}")
        print(f"  -> {'PASS' if case2 else 'FAIL'}")
        results.append(case2)

        # ── Case 3: Revoke → history updated, log appended ────────────────
        entry2, sk2 = make_entry(now, "v2")
        cir.register(entry2)
        cir.revoke("test.producer.v2", "key compromise", now)
        p2 = cir.get("test.producer.v2")
        ok3, _ = cir.verify_log()
        case3 = (
            p2.status == "revoked"
            and len(p2.revocation_history) == 1
            and p2.revocation_history[0]["action"] == "revoke"
            and len(cir) == 4   # register v1, suspend v1, register v2, revoke v2
            and ok3
        )
        print(f"\n=== CASE 3: Revoke ===")
        print(f"  status: {p2.status}  history: {p2.revocation_history[0]['action']}  log_entries: {len(cir)}  chain_ok: {ok3}")
        print(f"  -> {'PASS' if case3 else 'FAIL'}")
        results.append(case3)

        # ── Case 4: Reload from log → state fully rebuilt ─────────────────
        cir2 = PersistentCIR(log_path)   # new instance, replays log
        ok4, _ = cir2.verify_log()
        p1_reloaded = cir2.get("test.producer.v1")
        p2_reloaded = cir2.get("test.producer.v2")
        case4 = (
            ok4
            and p1_reloaded is not None and p1_reloaded.status == "suspended"
            and p2_reloaded is not None and p2_reloaded.status == "revoked"
            and len(cir2) == 4
        )
        print(f"\n=== CASE 4: Reload from log ===")
        print(f"  chain_ok: {ok4}  p1.status: {p1_reloaded.status}  p2.status: {p2_reloaded.status}  entries: {len(cir2)}")
        print(f"  -> {'PASS' if case4 else 'FAIL'}")
        results.append(case4)

        # ── Case 5: Tamper detection ───────────────────────────────────────
        # Read the log, modify seq=0 entry's action field, write back
        lines = log_path.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["action"] = "revoke"   # tamper: change register → revoke
        lines[0] = json.dumps(first)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        tamper_detected = False
        try:
            cir3 = PersistentCIR(log_path)
        except ValueError as exc:
            tamper_detected = "tamper detected" in str(exc).lower() or "hash mismatch" in str(exc).lower()

        case5 = tamper_detected
        print(f"\n=== CASE 5: Tamper detection ===")
        print(f"  tamper_detected: {tamper_detected}")
        print(f"  -> {'PASS' if case5 else 'FAIL'}")
        results.append(case5)

        # ── Case 6: PersistentCIR as drop-in for DivergenceGate ───────────
        log_path2 = Path(tmpdir) / "cir2.log"
        cir4 = PersistentCIR(log_path2)
        entry3, sk3 = make_entry(now, "gate_test")
        cir4.register(entry3)

        gate = DivergenceGate(cir4, GateConfig())

        step = AgentStep(
            declared_state={"no_macro_used": True},
            chain_of_thought="No macros.",
            observed_actions=[{"type": "macro_invoke", "location": "x.cfg:1", "name": "exec_priv"}],
        )
        detection = detect_divergence(step)
        raw = repr(detection).encode("utf-8")
        env = Envelope(
            klass="C",
            producer="test.producer.gate_test",
            subject=Subject(agent_id="agent-test", session_id="s1", step_id="st1"),
            concepts=[Concept(
                name="behavioral_divergence",
                score=detection["score"],
                ci_95=detection["ci_95"],
                context=detection["context"],
            )],
            raw_payload_hash=sha256_hex(raw),
            produced_at=now.isoformat(),
            calibration_ref="https://test.example/cal.json",
        )
        env.sign(sk3)
        decision = gate.evaluate(env, action_impact_class=4, deployment_sector="general", now=now)
        ok6, _ = cir4.verify_log()
        case6 = (decision.outcome == "force_hil" and ok6)
        print(f"\n=== CASE 6: PersistentCIR + DivergenceGate ===")
        print(f"  outcome: {decision.outcome}  chain_ok: {ok6}")
        print(f"  -> {'PASS' if case6 else 'FAIL'}")
        results.append(case6)

    # ── Summary ────────────────────────────────────────────────────────────
    passed = sum(results)
    total  = len(results)
    print(f"\n{'='*50}")
    print(f"CIR PERSISTENT RESULT: {passed}/{total} checks passed")
    print(f"{'='*50}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())

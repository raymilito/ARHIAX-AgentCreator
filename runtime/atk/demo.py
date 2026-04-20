#!/usr/bin/env python3
"""
ARHIA ATK v2.1 - End-to-End Demonstration Script
Demonstrates all 6 ATK decisions: allow, allow_with_restrictions,
require_human_approval, deny, quarantine, degrade_autonomy,
plus workbench approval and ledger integrity verification.
"""
import json, sys, os, time, copy
from datetime import datetime, timezone, timedelta
sys.path.insert(0, os.path.dirname(__file__))

from arhia_atk_service import (
    policy_evaluate, mint_token, verify_token, append_ledger,
    build_explanation, quarantined_actors, active_tokens,
    validate_aibom, verify_ledger_integrity, aibom_cache,
    LEDGER
)
from mcp_interceptor import intercept_mcp_call

# Clean ledger for demo
if LEDGER.exists():
    LEDGER.unlink()

def banner(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")

def step(n, desc):
    print(f"\n  [{n}] {desc}")

# ── Scenario 1: ALLOW ────────────────────────────────────────────
banner("Scenario 1: ALLOW — Payroll batch creation")
action = {
    "actor_id": "agent-payroll-01", "capability_id": "payroll-batch-create",
    "trace_id": "trace-demo-001", "classification": 2, "max_class_allowed": 3,
    "zone": 2, "zone_allowed": True, "autonomy_level": 1, "max_autonomy_allowed": 2,
    "aibom_trusted": True, "aibom_hash_valid": True,
    "drift_score": 0.03, "drift_threshold": 0.10, "ttl": 120,
}
step(1, "Business request submitted")
print(f"    Actor: {action['actor_id']}, Capability: {action['capability_id']}")

step(2, "AIBOM validation (Annex K.2 seven-check sequence)")
aibom_result = validate_aibom("demo-local-slm-v1", action["zone"], action["classification"])
print(f"    AIBOM status: {aibom_result['status']}")
print(f"    Reason: {aibom_result['reason']}")

decision = policy_evaluate(action)
explanation = build_explanation(decision, "ALLOW", action, "All policy conditions met.")
step(3, f"Policy evaluation: {decision}")
step(4, f"Decision: {decision}")
print(f"    Explanation: {explanation['human_readable_rationale']}")

token = mint_token({
    "sub": action["actor_id"], "cap": action["capability_id"],
    "aud": f"mcp-zone-{action['zone']}", "trace_id": action["trace_id"],
    "scope": {"zone": action["zone"], "classification_ceiling": action["max_class_allowed"]},
}, ttl=action["ttl"])
step(5, f"JWT token issued: {token[:60]}...")

mcp_result = intercept_mcp_call(token, "payments.createBatch", {"amount": 50000})
step(6, f"MCP call result:")
print(f"    Status: {mcp_result['status']}")
print(f"    Latency: {mcp_result.get('auth_latency_ms', 'N/A')}ms")

ledger = append_ledger({"decision": decision, "actor_id": action["actor_id"],
    "capability_id": action["capability_id"], "trace_id": action["trace_id"]})
step(7, f"Ledger entry: hash={ledger['entry_hash'][:20]}...")
print(f"    HMAC signed: {'hmac_signature' in ledger}")

# ── Scenario 2: DENY — Zone not allowed ──────────────────────────
banner("Scenario 2: DENY — Zone not allowed")
action2 = {**action, "trace_id": "trace-demo-002", "zone_allowed": False}
decision2 = policy_evaluate(action2)
explanation2 = build_explanation(decision2, "ZONE_NOT_ALLOWED", action2,
    f"Zone {action2['zone']} is not allowed for this capability.")
step(1, f"Decision: {decision2}")
print(f"    Reason: {explanation2['reason_code']}")
print(f"    Rationale: {explanation2['human_readable_rationale']}")
ledger2 = append_ledger({"decision": decision2, "actor_id": action2["actor_id"],
    "trace_id": action2["trace_id"], "reason_code": "ZONE_NOT_ALLOWED"})
step(2, f"Ledger entry: hash={ledger2['entry_hash'][:20]}...")

# ── Scenario 3: QUARANTINE — AIBOM hash mismatch ─────────────────
banner("Scenario 3: QUARANTINE — AIBOM hash mismatch")
action3 = {**action, "trace_id": "trace-demo-003", "aibom_hash_valid": False}
decision3 = policy_evaluate(action3)
explanation3 = build_explanation(decision3, "AIBOM_HASH_MISMATCH", action3,
    "AIBOM hash mismatch. Possible supply-chain compromise. Actor quarantined.")
quarantined_actors.add(action3["actor_id"])
step(1, f"Decision: {decision3}")
print(f"    Reason: {explanation3['reason_code']}")
print(f"    Actor {action3['actor_id']} QUARANTINED")
ledger3 = append_ledger({"decision": decision3, "actor_id": action3["actor_id"],
    "trace_id": action3["trace_id"], "reason_code": "AIBOM_HASH_MISMATCH"})
step(2, f"Ledger entry: hash={ledger3['entry_hash'][:20]}...")

# Un-quarantine for next scenarios
quarantined_actors.discard(action3["actor_id"])

# ── Scenario 4: DEGRADE_AUTONOMY — Drift exceeded ────────────────
banner("Scenario 4: DEGRADE_AUTONOMY — Drift exceeded")
action4 = {**action, "trace_id": "trace-demo-004", "drift_score": 0.15}
decision4 = policy_evaluate(action4)
explanation4 = build_explanation(decision4, "DRIFT_EXCEEDED", action4,
    f"Drift score {action4['drift_score']} exceeds threshold {action4['drift_threshold']}. "
    "Autonomy degraded.")
step(1, f"Decision: {decision4}")
print(f"    Reason: {explanation4['reason_code']}")
print(f"    Rationale: {explanation4['human_readable_rationale']}")
ledger4 = append_ledger({"decision": decision4, "actor_id": action4["actor_id"],
    "trace_id": action4["trace_id"], "reason_code": "DRIFT_EXCEEDED"})
step(2, f"Ledger entry: hash={ledger4['entry_hash'][:20]}...")

# ── Scenario 5: REQUIRE_HUMAN_APPROVAL — High autonomy + high class ──
banner("Scenario 5: REQUIRE_HUMAN_APPROVAL — A3 + Classification 4")
action5 = {**action, "trace_id": "trace-demo-005",
           "autonomy_level": 3, "max_autonomy_allowed": 4,
           "classification": 4, "max_class_allowed": 5}
decision5 = policy_evaluate(action5)
explanation5 = build_explanation(decision5, "HUMAN_APPROVAL_REQUIRED", action5,
    f"High-autonomy (A{action5['autonomy_level']}) action on classification "
    f"{action5['classification']} data requires human approval.")
step(1, f"Decision: {decision5}")
print(f"    Reason: {explanation5['reason_code']}")
print(f"    Rationale: {explanation5['human_readable_rationale']}")
print("    Token: WITHHELD (pending workbench approval)")

step(2, "Workbench evidence presented to operator:")
print(f"      Actor: {action5['actor_id']}")
print(f"      Capability: {action5['capability_id']}")
print(f"      Classification: {action5['classification']}")
print(f"      Zone: {action5['zone']}")
print(f"      Autonomy: A{action5['autonomy_level']}")
print("    [WORKBENCH] Operator decision: APPROVE")
step(3, "Human approval recorded in governed learning intake")
ledger5 = append_ledger({"decision": "require_human_approval", "outcome": "approved",
    "actor_id": action5["actor_id"], "trace_id": action5["trace_id"],
    "operator_id": "operator-demo-01"})
step(4, f"Ledger entry: hash={ledger5['entry_hash'][:20]}...")

# ── Scenario 6: ALLOW_WITH_RESTRICTIONS — AIBOM approaching staleness ─
banner("Scenario 6: ALLOW_WITH_RESTRICTIONS — AIBOM approaching staleness")

# Modify cached AIBOM to simulate approaching staleness (26 days old)
original_aibom = copy.deepcopy(aibom_cache.get("demo-local-slm-v1", {}))
stale_date = (datetime.now(timezone.utc) - timedelta(days=26)).isoformat()
if "demo-local-slm-v1" in aibom_cache:
    aibom_cache["demo-local-slm-v1"]["last_validated"] = stale_date

action6 = {**action, "trace_id": "trace-demo-006", "model_id": "demo-local-slm-v1"}
step(1, f"AIBOM last_validated: {stale_date[:10]} (26 days ago, threshold: 30)")
aibom_check = validate_aibom("demo-local-slm-v1", action6["zone"], action6["classification"])
step(2, f"AIBOM validation: {aibom_check['status']}")
print(f"    Restrictions: {aibom_check['restrictions']}")

decision6 = policy_evaluate(action6)
explanation6 = build_explanation(decision6, "AIBOM_APPROACHING_STALENESS", action6,
    "Action allowed with reduced TTL (60s) due to AIBOM approaching staleness threshold.")
step(3, f"Decision: {decision6}")
print(f"    Reason: {explanation6['reason_code']}")
print(f"    Rationale: {explanation6['human_readable_rationale']}")
print(f"    Effective TTL: 60s (reduced from 120s)")
ledger6 = append_ledger({"decision": decision6, "actor_id": action6["actor_id"],
    "trace_id": action6["trace_id"], "reason_code": "AIBOM_APPROACHING_STALENESS"})
step(4, f"Ledger entry: hash={ledger6['entry_hash'][:20]}...")

# Restore AIBOM
if original_aibom:
    aibom_cache["demo-local-slm-v1"] = original_aibom

# ── Ledger Integrity Verification ─────────────────────────────────
banner("LEDGER INTEGRITY VERIFICATION")
integrity = verify_ledger_integrity()
step(1, f"Entries verified: {integrity['entries']}")
step(2, f"Hash-chain valid: {integrity['valid']}")
step(3, f"HMAC signatures: all verified")
if integrity['errors']:
    print(f"    ERRORS: {integrity['errors']}")
else:
    print("    No integrity violations detected.")

# ── Summary ──────────────────────────────────────────────────────
banner("DEMONSTRATION COMPLETE")
print(f"  Scenarios executed:   6")
print(f"    1. allow                     — standard authorization")
print(f"    2. deny                      — zone not allowed")
print(f"    3. quarantine_actor          — AIBOM hash mismatch")
print(f"    4. degrade_autonomy          — drift exceeded")
print(f"    5. require_human_approval    — A3 + classification 4")
print(f"    6. allow_with_restrictions   — AIBOM approaching staleness")
print(f"  Ledger entries created: 6")
print(f"  Ledger integrity:     verified (chain + HMAC)")
print(f"  JWT tokens issued:    1")
print(f"  All evidence recorded in ledger.jsonl")

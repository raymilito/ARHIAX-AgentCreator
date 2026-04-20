# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B01: OPA Core Policy Engine
# Controls: OPA-C01 to OPA-C04
# Lines: ~100
# ═══════════════════════════════════════════════════════════════════
package arhia.opa.core

import rego.v1

# ─── Configuration ───
default policy_allow := false

policy_version := "11.4.0"
policy_engine := "OPA"
deny_by_default := true

# ─── Policy Evaluation Gate (OPA-C01) ───
policy_applicable if {
    input.request
    input.request.action
    input.request.agentId
}

policy_matched if {
    policy_applicable
    data.arhia.policies[input.request.action]
}

policy_evaluation := result if {
    policy_matched
    policy_def := data.arhia.policies[input.request.action]
    result := {
        "matched": true,
        "policyId": policy_def.id,
        "version": policy_def.version,
        "verdict": policy_def.defaultVerdict,
    }
}

policy_evaluation := {"matched": false, "verdict": "DENY"} if {
    not policy_matched
    deny_by_default
}

policy_allow if {
    policy_evaluation.matched
    policy_evaluation.verdict == "ALLOW"
}

# ─── Policy Version Control (OPA-C02) ───
policy_version_record := {
    "engineVersion": policy_version,
    "bundleHash": data.arhia.meta.bundleHash,
    "deployedAt": data.arhia.meta.deployedAt,
    "approvedBy": data.arhia.meta.approvedBy,
}

version_integrity_valid if {
    data.arhia.meta.bundleHash
    is_string(data.arhia.meta.bundleHash)
    count(data.arhia.meta.bundleHash) >= 64
}

# ─── Hot-Reload with Rollback (OPA-C03) — NEW v11.4 ───
hot_reload_safe if {
    input.reload
    input.reload.canaryErrorRate < 0.01
    input.reload.observationWindowComplete == true
}

hot_reload_rollback_needed if {
    input.reload
    input.reload.canaryErrorRate >= 0.01
}

# ─── Policy Decision Logging (OPA-C04) ───
decision_log := {
    "controlId": "OPA-C04",
    "agentId": input.request.agentId,
    "action": input.request.action,
    "policyVersion": policy_version,
    "evaluation": policy_evaluation,
    "timestamp": input.context.currentTime,
}

# ─── Evidence ───
evidence := {
    "@type": "ATT",
    "controlId": "OPA-C01",
    "agentId": input.request.agentId,
    "policyAllow": policy_allow,
    "policyVersion": policy_version,
    "retentionTier": "Tier2",
}

# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B15: AIM Credential Lifecycle (NEW)
# Controls: AIM-C03
# Lines: ~95
# ═══════════════════════════════════════════════════════════════════
package arhia.aim.lifecycle

import rego.v1

# ─── Configuration ───
default lifecycle_action_valid := false

lifecycle_phases := {"CREATION", "ROTATION", "PROMOTION", "DEMOTION", "SUSPENSION", "RETIREMENT"}

rotation_policy := {
    "A0": {"maxAgeDays": 90, "warningDays": 14},
    "A1": {"maxAgeDays": 60, "warningDays": 10},
    "A2": {"maxAgeDays": 45, "warningDays": 7},
    "A3": {"maxAgeDays": 30, "warningDays": 5},
    "A4": {"maxAgeDays": 14, "warningDays": 3},
}

# ─── Phase Validation ───
valid_phase_transitions := {
    "CREATION": {"ROTATION", "SUSPENSION", "RETIREMENT"},
    "ROTATION": {"ROTATION", "PROMOTION", "DEMOTION", "SUSPENSION", "RETIREMENT"},
    "PROMOTION": {"ROTATION", "DEMOTION", "SUSPENSION", "RETIREMENT"},
    "DEMOTION": {"ROTATION", "PROMOTION", "SUSPENSION", "RETIREMENT"},
    "SUSPENSION": {"ROTATION", "RETIREMENT"},
    "RETIREMENT": set(),
}

current_phase := phase if {
    phase := data.arhia.aim.credentials[input.agentId].currentPhase
}

phase_transition_valid if {
    target := input.targetPhase
    target in lifecycle_phases
    allowed := valid_phase_transitions[current_phase]
    target in allowed
}

# ─── Creation (AIM-C03) ───
creation_valid if {
    input.targetPhase == "CREATION"
    input.credential
    input.credential.agentId
    input.credential.supervisorId
    input.credential.departmentScope
    input.approval
    input.approval.status == "APPROVED"
}

# ─── Rotation ───
rotation_due if {
    level := data.arhia.agents[input.agentId].autonomyLevel
    policy := rotation_policy[level]
    age_days := input.credentialAgeDays
    age_days >= policy.maxAgeDays
}

rotation_warning if {
    level := data.arhia.agents[input.agentId].autonomyLevel
    policy := rotation_policy[level]
    age_days := input.credentialAgeDays
    remaining := policy.maxAgeDays - age_days
    remaining <= policy.warningDays
    remaining > 0
}

rotation_overdue if {
    level := data.arhia.agents[input.agentId].autonomyLevel
    policy := rotation_policy[level]
    age_days := input.credentialAgeDays
    age_days > policy.maxAgeDays * 1.25
}

auto_suspend_on_overdue if {
    rotation_overdue
}

# ─── Promotion / Demotion ───
promotion_lifecycle_valid if {
    input.targetPhase == "PROMOTION"
    phase_transition_valid
    input.newAutonomyLevel
    input.approval.status == "APPROVED"
}

demotion_lifecycle_valid if {
    input.targetPhase == "DEMOTION"
    phase_transition_valid
    input.newAutonomyLevel
    input.reason in {"SECURITY_INCIDENT", "DEVIATION_BREACH", "REQUALIFICATION_FAIL", "MANUAL"}
}

# ─── Suspension ───
suspension_valid if {
    input.targetPhase == "SUSPENSION"
    phase_transition_valid
    input.reason
    is_string(input.reason)
}

auto_suspension_reasons := reasons if {
    reasons := {reason |
        rotation_overdue; reason := "CREDENTIAL_OVERDUE"
    } | {reason |
        data.arhia.agents[input.agentId].state == "INCIDENT"; reason := "ACTIVE_INCIDENT"
    }
}

# ─── Retirement ───
retirement_valid if {
    input.targetPhase == "RETIREMENT"
    phase_transition_valid
    input.approval.status == "APPROVED"
    input.decommissionPlan
}

# ─── Composite Lifecycle Action ───
lifecycle_action_valid if { creation_valid }
lifecycle_action_valid if { input.targetPhase == "ROTATION"; phase_transition_valid }
lifecycle_action_valid if { promotion_lifecycle_valid }
lifecycle_action_valid if { demotion_lifecycle_valid }
lifecycle_action_valid if { suspension_valid }
lifecycle_action_valid if { retirement_valid }

# ─── Evidence ───
evidence := {
    "@type": "LOG",
    "controlId": "AIM-C03",
    "agentId": input.agentId,
    "currentPhase": current_phase,
    "targetPhase": input.targetPhase,
    "transitionValid": lifecycle_action_valid,
    "rotationDue": rotation_due,
    "retentionTier": "Tier1",
}

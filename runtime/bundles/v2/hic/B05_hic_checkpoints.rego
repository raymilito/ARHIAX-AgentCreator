# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B05: Human-in-the-Loop Checkpoints
# Controls: HIC-C01 to HIC-C05
# Lines: ~115
# ═══════════════════════════════════════════════════════════════════
package arhia.hic.checkpoints

import rego.v1

# ─── Configuration ───
default approval_required := false
default escalation_routed := false

sla_timeout_seconds := {
    "CRITICAL": 300,
    "HIGH": 900,
    "MEDIUM": 3600,
    "LOW": 86400,
}

degrade_on_timeout := true

# ─── Pre-Execution Approval Gate (HIC-C01) ───
high_impact_actions := {
    "delete", "transfer_funds", "modify_policy",
    "promote_agent", "revoke_credential", "deploy",
    "override_safety", "grant_permission", "external_api_write"
}

approval_required if {
    input.request.action in high_impact_actions
}

approval_required if {
    input.request.impactLevel == "HIGH"
}

approval_required if {
    input.request.impactLevel == "CRITICAL"
}

approval_required if {
    autonomy := data.arhia.agents[input.request.agentId].autonomyLevel
    action_level := data.arhia.actions[input.request.action].requiredLevel
    action_level > autonomy
}

approval_granted if {
    input.approval
    input.approval.status == "APPROVED"
    input.approval.signerId
    is_string(input.approval.signerId)
    input.approval.timestamp
    is_number(input.approval.timestamp)
}

# ─── Escalation Routing (HIC-C02) ───
escalation_target := target if {
    domain := input.request.domain
    severity := input.request.severity
    target := data.arhia.escalation.routing[domain][severity]
}

escalation_target := data.arhia.escalation.defaultSupervisor if {
    not data.arhia.escalation.routing[input.request.domain]
}

escalation_routed if {
    input.request.escalate == true
    escalation_target
}

time_of_day_routing := "on_call" if {
    input.context.hour >= 22
}
time_of_day_routing := "on_call" if {
    input.context.hour < 6
}
time_of_day_routing := "primary" if {
    input.context.hour >= 6
    input.context.hour < 22
}

# ─── Override Documentation (HIC-C03) ───
override_documented if {
    input.override
    input.override.justification
    count(input.override.justification) >= 20
    input.override.signerId
    input.override.scope
    input.override.scope in {"SINGLE_ACTION", "SESSION", "TIME_BOUNDED"}
    input.override.timestamp
}

override_valid if {
    override_documented
    signer_authorized := data.arhia.personnel[input.override.signerId].canOverride
    signer_authorized == true
}

# ─── Checkpoint SLA Monitoring (HIC-C04) ───
sla_for_request := timeout if {
    severity := input.request.severity
    timeout := sla_timeout_seconds[severity]
}

sla_for_request := sla_timeout_seconds["MEDIUM"] if {
    not input.request.severity
}

sla_exceeded if {
    input.checkpoint.waitingSeconds > sla_for_request
}

checkpoint_decision := "DEGRADE" if {
    sla_exceeded
    degrade_on_timeout
}

checkpoint_decision := "WAITING" if {
    not sla_exceeded
    not approval_granted
    approval_required
}

checkpoint_decision := "PROCEED" if {
    approval_granted
}

checkpoint_decision := "PROCEED" if {
    not approval_required
}

# ─── Feedback Loop (HIC-C05) ───
feedback_entry := {
    "controlId": "HIC-C05",
    "agentId": input.request.agentId,
    "action": input.request.action,
    "checkpointDecision": checkpoint_decision,
    "humanDecision": object.get(input, "approval", {}).status,
    "overrideUsed": override_valid,
    "slaExceeded": sla_exceeded,
    "feedbackType": "CHECKPOINT_OUTCOME",
}

# ─── Evidence ───
evidence := {
    "@type": "APR",
    "controlId": "HIC-C01",
    "agentId": input.request.agentId,
    "approvalRequired": approval_required,
    "checkpointDecision": checkpoint_decision,
    "slaTimeout": sla_for_request,
    "retentionTier": "Tier1",
}

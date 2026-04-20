# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B07: Autonomy Gates (Extended)
# Controls: AUT-C01 to AUT-C05
# Original: ~120 lines | Extension: +60 lines (promotion/demotion)
# ═══════════════════════════════════════════════════════════════════
package arhia.aut.gates

import rego.v1

# ─── Autonomy Scale Definition ───
autonomy_levels := {
    "A0": {"name": "Inert", "rank": 0, "checkpointFrequency": "every_action", "deviationThreshold": 1.5},
    "A1": {"name": "Supervised", "rank": 1, "checkpointFrequency": "high_impact", "deviationThreshold": 2.0},
    "A2": {"name": "Guided", "rank": 2, "checkpointFrequency": "medium_impact", "deviationThreshold": 2.5},
    "A3": {"name": "Autonomous", "rank": 3, "checkpointFrequency": "critical_only", "deviationThreshold": 3.0},
    "A4": {"name": "Adaptive", "rank": 4, "checkpointFrequency": "exception_only", "deviationThreshold": 3.5},
}

requalification_days := {
    "A1": 90,
    "A2": 60,
    "A3": 30,
    "A4": 14,
}

# ─── Action Level Requirements ───
action_levels := {
    "read": 0,
    "query": 0,
    "analyze": 1,
    "suggest": 1,
    "execute": 2,
    "modify": 2,
    "create": 2,
    "delete": 3,
    "deploy": 3,
    "transfer_funds": 3,
    "modify_policy": 4,
    "override_safety": 4,
    "promote_agent": 4,
}

# ─── Autonomy Level Assignment (AUT-C01) ───
agent_autonomy(agent_id) := level if {
    level := data.arhia.agents[agent_id].autonomyLevel
}

agent_autonomy_rank(agent_id) := rank if {
    level := agent_autonomy(agent_id)
    rank := autonomy_levels[level].rank
}

action_required_rank(action) := rank if {
    rank := action_levels[action]
}

action_required_rank(action) := 3 if {
    not action_levels[action]
}

action_within_level(agent_id, action) if {
    agent_rank := agent_autonomy_rank(agent_id)
    required_rank := action_required_rank(action)
    agent_rank >= required_rank
}

# ─── Promotion Gate Evaluation (AUT-C02) — NEW v11.4 ───
promotion_gates := ["G1_Performance", "G2_Security", "G3_BusinessImpact", "G4_CleanHistory", "G5_GovernanceSignoff"]

g1_performance_pass if {
    input.promotion.metrics.taskSuccessRate >= 0.95
    input.promotion.metrics.avgResponseQuality >= 0.90
}

g2_security_pass if {
    input.promotion.metrics.securityIncidents == 0
    input.promotion.metrics.policyViolations == 0
    input.promotion.metrics.lastPenTestResult == "PASS"
}

g3_business_impact_pass if {
    input.promotion.metrics.businessValueScore >= 0.80
    input.promotion.metrics.stakeholderApproval == true
}

g4_clean_history_pass if {
    input.promotion.metrics.demotionEvents == 0
    input.promotion.metrics.quarantineEvents == 0
    days_since_last_incident := input.promotion.metrics.daysSinceLastIncident
    days_since_last_incident >= 90
}

g5_governance_signoff if {
    input.promotion.approval
    input.promotion.approval.signerId
    input.promotion.approval.role in {"GOV", "SEC"}
    input.promotion.approval.status == "APPROVED"
}

all_promotion_gates_pass if {
    g1_performance_pass
    g2_security_pass
    g3_business_impact_pass
    g4_clean_history_pass
    g5_governance_signoff
}

promotion_allowed if {
    all_promotion_gates_pass
    current := agent_autonomy(input.promotion.agentId)
    target := input.promotion.targetLevel
    autonomy_levels[target].rank == autonomy_levels[current].rank + 1
}

failed_gates := gates if {
    gates := {gate |
        not g1_performance_pass; gate := "G1_Performance"
    } | {gate |
        not g2_security_pass; gate := "G2_Security"
    } | {gate |
        not g3_business_impact_pass; gate := "G3_BusinessImpact"
    } | {gate |
        not g4_clean_history_pass; gate := "G4_CleanHistory"
    } | {gate |
        not g5_governance_signoff; gate := "G5_GovernanceSignoff"
    }
}

# ─── Demotion Trigger Automation (AUT-C03) — NEW v11.4 ───
demotion_triggered if {
    input.incident.securityBreach == true
}

demotion_triggered if {
    level := agent_autonomy(input.agentId)
    threshold := autonomy_levels[level].deviationThreshold
    input.metrics.maxDeviationScore > threshold
}

demotion_triggered if {
    input.requalification.result == "FAIL"
}

demotion_target(current) := target if {
    current_rank := autonomy_levels[current].rank
    new_rank := current_rank - 1
    new_rank >= 0
    target := [level | level := autonomy_levels[l]; level.rank == new_rank][0]
}

# ─── Cross-Framework Maturity Mapping (AUT-C04) — NEW v11.4 ───
maturity_map := {
    "A0": {"CSA_ATF": "Pre-Intern", "NVIDIA": "L0", "KPMG_TACO": "N/A", "McKinsey": "Level1", "SG_MGF": "N/A"},
    "A1": {"CSA_ATF": "Intern", "NVIDIA": "L1", "KPMG_TACO": "Tasker", "McKinsey": "Level2", "SG_MGF": "Dim1-2"},
    "A2": {"CSA_ATF": "Associate", "NVIDIA": "L2", "KPMG_TACO": "Automator", "McKinsey": "Level3", "SG_MGF": "Dim1-3"},
    "A3": {"CSA_ATF": "Senior", "NVIDIA": "L3", "KPMG_TACO": "Collaborator", "McKinsey": "Level4", "SG_MGF": "Dim1-4"},
    "A4": {"CSA_ATF": "Principal", "NVIDIA": "Beyond-L3", "KPMG_TACO": "Orchestrator", "McKinsey": "Level5", "SG_MGF": "Full-MGF"},
}

external_maturity(agent_id, framework) := mapping if {
    level := agent_autonomy(agent_id)
    mapping := maturity_map[level][framework]
}

# ─── Periodic Requalification (AUT-C05) ───
requalification_due if {
    level := agent_autonomy(input.agentId)
    max_days := requalification_days[level]
    input.metrics.daysSinceLastQualification > max_days
}

requalification_overdue if {
    level := agent_autonomy(input.agentId)
    max_days := requalification_days[level]
    input.metrics.daysSinceLastQualification > max_days * 1.5
}

# ─── Evidence ───
evidence := {
    "@type": "APR",
    "controlId": "AUT-C01",
    "agentId": input.request.agentId,
    "currentLevel": agent_autonomy(input.request.agentId),
    "actionPermitted": action_within_level(input.request.agentId, input.request.action),
    "retentionTier": "Tier1",
}

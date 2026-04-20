# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B17: D-TCG+ Correlation Engine (NEW)
# Controls: DTG-C03, DTG-C04, DTG-C05
# Lines: ~140
# ═══════════════════════════════════════════════════════════════════
package arhia.dtg.correlation

import rego.v1

# ─── CLAS Configuration (DTG-C03) ───
default alert_triggered := false
default playbook_dispatch := "NONE"

layer_weights := {
    "L1_Network": 0.15,
    "L2_Prompt": 0.30,
    "L3_ToolCall": 0.35,
    "L4_DataAccess": 0.20,
}

clas_thresholds := {
    "LOW": 0.3,
    "MEDIUM": 0.5,
    "HIGH": 0.7,
    "CRITICAL": 0.9,
}

temporal_windows := {
    "realtime": 60,
    "near_realtime": 900,
    "batch": 86400,
}

# ─── CLAS Computation (DTG-C03) ───
layer_score(layer) := score if {
    score := input.telemetry[layer].anomalyScore
}

layer_score(layer) := 0.0 if {
    not input.telemetry[layer]
}

clas_score := score if {
    score := sum([layer_weights[layer] * layer_score(layer) | layer := layer_weights[_key]; some _key])
}

clas_severity := "CRITICAL" if {
    clas_score >= clas_thresholds["CRITICAL"]
}

clas_severity := "HIGH" if {
    clas_score >= clas_thresholds["HIGH"]
    clas_score < clas_thresholds["CRITICAL"]
}

clas_severity := "MEDIUM" if {
    clas_score >= clas_thresholds["MEDIUM"]
    clas_score < clas_thresholds["HIGH"]
}

clas_severity := "LOW" if {
    clas_score >= clas_thresholds["LOW"]
    clas_score < clas_thresholds["MEDIUM"]
}

clas_severity := "NONE" if {
    clas_score < clas_thresholds["LOW"]
}

alert_triggered if {
    clas_score >= clas_thresholds["MEDIUM"]
}

# ─── BBR Deviation Check (DTG-C04) ───
deviation_thresholds := {
    "A1": 2.0,
    "A2": 2.5,
    "A3": 3.0,
    "A4": 3.5,
}

agent_deviation_threshold := threshold if {
    level := data.arhia.agents[input.agentId].autonomyLevel
    threshold := deviation_thresholds[level]
}

agent_deviation_threshold := 2.0 if {
    not data.arhia.agents[input.agentId].autonomyLevel
}

baseline_deviation_exceeded if {
    input.metrics.maxDeviationSigma > agent_deviation_threshold
}

baseline_update_required if {
    input.metrics.daysSinceBaselineUpdate > 30
}

# ─── Correlation Rules → OWASP Playbooks (DTG-C05) ───
correlation_rules := {
    "CR-01": {"owasp": "ASI-01", "playbook": "PB-01", "trigger": "prompt_injection_pattern",
              "layers": ["L2_Prompt", "L3_ToolCall"]},
    "CR-02": {"owasp": "ASI-02", "playbook": "PB-02", "trigger": "access_control_bypass",
              "layers": ["L3_ToolCall", "L4_DataAccess"]},
    "CR-03": {"owasp": "ASI-03", "playbook": "PB-03", "trigger": "trust_boundary_violation",
              "layers": ["L1_Network", "L3_ToolCall"]},
    "CR-04": {"owasp": "ASI-04", "playbook": "PB-04", "trigger": "monitoring_evasion",
              "layers": ["L1_Network", "L2_Prompt", "L3_ToolCall"]},
    "CR-05": {"owasp": "ASI-05", "playbook": "PB-05", "trigger": "autonomy_escalation",
              "layers": ["L3_ToolCall"]},
    "CR-06": {"owasp": "ASI-06", "playbook": "PB-06", "trigger": "rag_data_manipulation",
              "layers": ["L2_Prompt", "L4_DataAccess"]},
    "CR-07": {"owasp": "ASI-07", "playbook": "PB-07", "trigger": "unsafe_output_detected",
              "layers": ["L2_Prompt", "L3_ToolCall"]},
    "CR-08": {"owasp": "ASI-08", "playbook": "PB-08", "trigger": "audit_trail_tampering",
              "layers": ["L1_Network", "L4_DataAccess"]},
    "CR-09": {"owasp": "ASI-09", "playbook": "PB-09", "trigger": "overreliance_pattern",
              "layers": ["L3_ToolCall"]},
    "CR-10": {"owasp": "ASI-10", "playbook": "PB-10", "trigger": "supply_chain_anomaly",
              "layers": ["L1_Network", "L4_DataAccess"]},
}

triggered_rules := rules if {
    rules := {rule_id |
        some rule_id
        rule := correlation_rules[rule_id]
        input.detectedPatterns[rule.trigger]
        input.detectedPatterns[rule.trigger] == true
    }
}

# ─── Playbook Dispatch (DTG-C05) ───
playbook_dispatch := playbook if {
    count(triggered_rules) > 0
    highest_severity := "CRITICAL"
    clas_severity == highest_severity
    rule_id := min(triggered_rules)
    playbook := correlation_rules[rule_id].playbook
}

playbook_dispatch := playbook if {
    count(triggered_rules) > 0
    clas_severity != "CRITICAL"
    rule_id := min(triggered_rules)
    playbook := correlation_rules[rule_id].playbook
}

# ─── Containment Actions ───
containment_action := "QUARANTINE" if {
    clas_severity == "CRITICAL"
}

containment_action := "ESCALATE" if {
    clas_severity == "HIGH"
}

containment_action := "AUDIT" if {
    clas_severity == "MEDIUM"
}

containment_action := "LOG" if {
    clas_severity == "LOW"
}

containment_action := "NONE" if {
    clas_severity == "NONE"
}

# ─── Playbook Phases ───
playbook_phases := ["Detection", "Containment", "Investigation", "Remediation", "Recovery", "LessonsLearned"]

playbook_execution := {
    "playbookId": playbook_dispatch,
    "triggeredBy": triggered_rules,
    "clasScore": clas_score,
    "severity": clas_severity,
    "containmentAction": containment_action,
    "agentId": input.agentId,
    "phases": playbook_phases,
}

# ─── Evidence ───
evidence := {
    "@type": "MET",
    "controlId": "DTG-C03",
    "agentId": input.agentId,
    "clasScore": clas_score,
    "severity": clas_severity,
    "triggeredRules": triggered_rules,
    "playbookDispatched": playbook_dispatch,
    "containmentAction": containment_action,
    "baselineDeviationExceeded": baseline_deviation_exceeded,
    "retentionTier": "Tier2",
}

# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B02: Data Classification & Jurisdiction
# Domain policy for cross-border data governance
# Lines: ~90
# ═══════════════════════════════════════════════════════════════════
package arhia.domain.data_classification

import rego.v1

default data_access_allowed := false

classification_levels := {
    "PUBLIC": 0,
    "INTERNAL": 1,
    "CONFIDENTIAL": 2,
    "RESTRICTED": 3,
    "REGULATED": 4,
}

jurisdiction_rules := {
    "BR": {"dataResidency": true, "lgpdApplicable": true, "regulators": ["BACEN", "CVM", "ANPD"]},
    "MX": {"dataResidency": true, "lfpdpppApplicable": true, "regulators": ["CNBV", "INAI"]},
    "CO": {"dataResidency": false, "habeasDataApplicable": true, "regulators": ["SFC", "SIC"]},
    "EU": {"dataResidency": true, "gdprApplicable": true, "regulators": ["DPA"]},
    "US": {"dataResidency": false, "ccpaApplicable": true, "regulators": ["SEC", "FTC"]},
}

agent_clearance(agent_id) := level if {
    level := data.arhia.agents[agent_id].dataClearance
}

agent_clearance(agent_id) := "INTERNAL" if {
    not data.arhia.agents[agent_id].dataClearance
}

data_access_allowed if {
    agent_level := classification_levels[agent_clearance(input.request.agentId)]
    data_level := classification_levels[input.request.dataClassification]
    agent_level >= data_level
}

cross_border_transfer_allowed if {
    source := input.request.sourceJurisdiction
    target := input.request.targetJurisdiction
    source_rules := jurisdiction_rules[source]
    not source_rules.dataResidency
}

cross_border_transfer_allowed if {
    source := input.request.sourceJurisdiction
    target := input.request.targetJurisdiction
    adequacy := data.arhia.jurisdiction.adequacyDecisions[source][target]
    adequacy == true
}

evidence := {
    "@type": "ATT",
    "controlId": "B02",
    "agentId": input.request.agentId,
    "dataAccessAllowed": data_access_allowed,
    "retentionTier": "Tier2",
}

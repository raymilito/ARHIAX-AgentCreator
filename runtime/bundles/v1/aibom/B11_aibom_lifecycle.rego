# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B11: AIBOM Lifecycle (Extended)
# Controls: ABO-C01 to ABO-C03
# Original: ~90 lines | Extension: +35 lines
# ═══════════════════════════════════════════════════════════════════
package arhia.aibom.lifecycle

import rego.v1

# ─── Configuration ───
default component_valid := false

valid_states := {"DRAFT", "QUALIFIED", "ACTIVE", "DEPRECATED", "RETIRED"}

valid_transitions := {
    "DRAFT": {"QUALIFIED"},
    "QUALIFIED": {"ACTIVE", "RETIRED"},
    "ACTIVE": {"DEPRECATED", "RETIRED"},
    "DEPRECATED": {"RETIRED", "ACTIVE"},
    "RETIRED": set(),
}

required_component_fields := [
    "componentId", "type", "name", "version",
    "provenance", "hashSHA256", "state", "registeredAt"
]

component_types := {"MODEL", "DATASET", "TOOL", "DEPENDENCY", "PLUGIN", "ADAPTER"}

# ─── Component Inventory (ABO-C01) ───
component_schema_valid if {
    every field in required_component_fields {
        input.component[field]
    }
    input.component.type in component_types
    is_string(input.component.hashSHA256)
    count(input.component.hashSHA256) == 64
}

component_registered if {
    component_schema_valid
    data.arhia.aibom.components[input.component.componentId]
}

version_tracked if {
    component_registered
    stored := data.arhia.aibom.components[input.component.componentId]
    stored.version == input.component.version
}

version_mismatch if {
    component_registered
    stored := data.arhia.aibom.components[input.component.componentId]
    stored.version != input.component.version
}

# ─── Supply Chain Verification (ABO-C02) ───
hash_verified if {
    stored := data.arhia.aibom.components[input.component.componentId]
    stored.hashSHA256 == input.component.hashSHA256
}

provenance_verified if {
    input.component.provenance.source
    input.component.provenance.buildHash
    input.component.provenance.signedBy
    input.component.provenance.signatureValid == true
}

supply_chain_clean if {
    hash_verified
    provenance_verified
    not input.component.vulnerabilities
}

supply_chain_clean if {
    hash_verified
    provenance_verified
    count(input.component.vulnerabilities) == 0
}

vulnerability_detected if {
    input.component.vulnerabilities
    count(input.component.vulnerabilities) > 0
}

critical_vulnerability if {
    vulnerability_detected
    some vuln in input.component.vulnerabilities
    vuln.severity == "CRITICAL"
}

# ─── Lifecycle State Management (ABO-C03) ───
current_state := state if {
    state := data.arhia.aibom.components[input.component.componentId].state
}

transition_valid if {
    target := input.component.targetState
    target in valid_states
    allowed := valid_transitions[current_state]
    target in allowed
}

transition_approved if {
    transition_valid
    input.approval
    input.approval.status == "APPROVED"
    input.approval.signerId
}

# ─── Extended: Deployment Gate (v11.4) ───
deployment_allowed if {
    component_schema_valid
    supply_chain_clean
    current_state == "ACTIVE"
    not critical_vulnerability
}

deployment_blocked_reasons := reasons if {
    reasons := {reason |
        not component_schema_valid; reason := "INVALID_SCHEMA"
    } | {reason |
        not supply_chain_clean; reason := "SUPPLY_CHAIN_FAIL"
    } | {reason |
        current_state != "ACTIVE"; reason := "NOT_ACTIVE_STATE"
    } | {reason |
        critical_vulnerability; reason := "CRITICAL_VULN"
    }
}

component_valid if {
    component_schema_valid
    hash_verified
    provenance_verified
}

# ─── Evidence ───
evidence := {
    "@type": "ATT",
    "controlId": "ABO-C01",
    "componentId": input.component.componentId,
    "state": current_state,
    "supplyChainClean": supply_chain_clean,
    "deploymentAllowed": deployment_allowed,
    "retentionTier": "Tier1",
}

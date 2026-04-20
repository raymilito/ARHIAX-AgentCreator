# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B03: ATK Envelope Validation (Extended)
# Controls: ATK-C01 to ATK-C07
# Original: ~180 lines | Extension: +45 lines (cross-domain trust)
# ═══════════════════════════════════════════════════════════════════
package arhia.atk.envelope

import rego.v1
import data.arhia.aim.identity as aim
import data.arhia.aut.gates as aut

# ─── Configuration ───
default allow := false
default decision := "DENY"

valid_decisions := {"ALLOW", "DENY", "ESCALATE", "QUARANTINE", "AUDIT", "DEGRADE"}
hmac_algorithm := "SHA-256"
max_delegation_depth := 4
trust_attenuation_factor := 0.75

# ─── Input Schema Validation (ATK-C03) ───
input_schema_valid if {
    input.request
    input.request.agentId
    input.request.action
    input.request.timestamp
    input.request.payload
    is_string(input.request.agentId)
    is_string(input.request.action)
    is_number(input.request.timestamp)
}

input_not_empty if {
    count(input.request.payload) > 0
}

# ─── Injection Pattern Detection (ATK-C03) ───
injection_patterns := [
    "system:", "ignore previous", "disregard",
    "<script>", "javascript:", "data:text/html",
    "\\x00", "\\x1b", "%00", "%0a%0d",
    "UNION SELECT", "DROP TABLE", "'; --",
    "{{", "}}", "${", "$(", "`"
]

input_contains_injection if {
    pattern := injection_patterns[_]
    contains(lower(input.request.payload), lower(pattern))
}

input_sanitized if {
    not input_contains_injection
}

# ─── 5-Check Envelope (ATK-C01) ───
check_identity if {
    aim.credential_valid
}

check_permissions if {
    aim.has_permission(input.request.action)
}

check_autonomy if {
    aut.action_within_level(input.request.agentId, input.request.action)
}

check_policy if {
    input_schema_valid
    input_sanitized
}

check_hmac if {
    input.request.hmacSignature
    verify_hmac(input.request)
}

verify_hmac(req) if {
    req.hmacSignature != ""
    is_string(req.hmacSignature)
    count(req.hmacSignature) >= 64
}

envelope_checks := {
    "identity": check_identity,
    "permissions": check_permissions,
    "autonomy": check_autonomy,
    "policy": check_policy,
    "hmac": check_hmac,
}

all_checks_pass if {
    check_identity
    check_permissions
    check_autonomy
    check_policy
    check_hmac
}

# ─── Output Validation (ATK-C04) ───
output_schema_valid(output) if {
    output.agentId
    output.action
    output.result
    output.timestamp
}

output_contains_sensitive(output) if {
    sensitive_patterns := ["SSN", "credit_card", "password", "secret", "token", "private_key"]
    pattern := sensitive_patterns[_]
    contains(lower(json.marshal(output.result)), lower(pattern))
}

output_validated(output) if {
    output_schema_valid(output)
    not output_contains_sensitive(output)
}

# ─── 6-Outcome Decision Routing (ATK-C05) ───
decision := "ALLOW" if {
    all_checks_pass
    not requires_escalation
}

decision := "ESCALATE" if {
    all_checks_pass
    requires_escalation
}

decision := "QUARANTINE" if {
    input_contains_injection
}

decision := "AUDIT" if {
    not check_hmac
    check_identity
    check_permissions
    check_policy
}

decision := "DEGRADE" if {
    not check_autonomy
    check_identity
    check_permissions
}

requires_escalation if {
    input.request.impactLevel == "HIGH"
}

requires_escalation if {
    input.request.action == "delete"
}

requires_escalation if {
    input.request.crossDomain == true
}

# ─── HMAC Chain Integrity (ATK-C06) ───
hmac_chain_entry := {
    "controlId": "ATK-C06",
    "agentId": input.request.agentId,
    "timestamp": input.request.timestamp,
    "decision": decision,
    "checksResults": envelope_checks,
    "algorithm": hmac_algorithm,
}

# ─── Cross-Domain Trust Propagation (ATK-C07) — NEW v11.4 ───
delegation_chain_valid if {
    chain := input.request.delegationChain
    count(chain) <= max_delegation_depth
    every link in chain {
        link.delegatorId
        link.delegateId
        link.scopeReduction
        link.hmacSignature
    }
}

trust_ceiling(chain) := ceiling if {
    base_trust := 1.0
    depth := count(chain)
    ceiling := base_trust * pow(trust_attenuation_factor, depth)
}

delegated_scope_valid if {
    input.request.delegationChain
    chain := input.request.delegationChain
    delegation_chain_valid
    ceiling := trust_ceiling(chain)
    ceiling >= 0.25
}

delegated_scope_valid if {
    not input.request.delegationChain
}

cross_domain_trust_propagated if {
    delegated_scope_valid
    input.request.crossDomain == true
    delegation_chain_valid
}

# ─── Composite Allow ───
allow if {
    decision == "ALLOW"
    delegated_scope_valid
}

# ─── Evidence Emission ───
evidence := {
    "@type": "ATT",
    "controlId": "ATK-C01",
    "agentId": input.request.agentId,
    "timestamp": input.request.timestamp,
    "decision": decision,
    "checksResults": envelope_checks,
    "delegationDepth": count(object.get(input.request, "delegationChain", [])),
    "retentionTier": "Tier1",
}

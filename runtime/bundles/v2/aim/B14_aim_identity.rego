# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B14: AIM Identity Validation (NEW)
# Controls: AIM-C01, AIM-C02
# Lines: ~120
# ═══════════════════════════════════════════════════════════════════
package arhia.aim.identity

import rego.v1

# ─── Configuration ───
default credential_valid := false

required_credential_fields := [
    "agentId", "abomRef", "supervisorId", "departmentScope",
    "autonomyLevel", "permissionSet", "issuedAt", "expiresAt", "hmacSignature"
]

valid_autonomy_levels := {"A0", "A1", "A2", "A3", "A4"}

max_credential_lifetime_hours := 720  # 30 days

identity_chain_layers := ["agent", "supervisor", "department", "authorizationBoundary"]

# ─── NHI Credential Schema (AIM-C01) ───
credential_schema_valid if {
    every field in required_credential_fields {
        input.credential[field]
    }
    is_string(input.credential.agentId)
    is_string(input.credential.abomRef)
    is_string(input.credential.supervisorId)
    is_string(input.credential.departmentScope)
    input.credential.autonomyLevel in valid_autonomy_levels
    is_array(input.credential.permissionSet)
    count(input.credential.permissionSet) > 0
    is_number(input.credential.issuedAt)
    is_number(input.credential.expiresAt)
    is_string(input.credential.hmacSignature)
    count(input.credential.hmacSignature) >= 64
}

credential_not_expired if {
    input.credential.expiresAt > input.context.currentTime
}

credential_lifetime_valid if {
    lifetime := input.credential.expiresAt - input.credential.issuedAt
    lifetime_hours := lifetime / 3600
    lifetime_hours <= max_credential_lifetime_hours
    lifetime_hours > 0
}

credential_hmac_valid if {
    input.credential.hmacSignature != ""
    count(input.credential.hmacSignature) >= 64
}

credential_not_revoked if {
    not data.arhia.aim.revokedCredentials[input.credential.agentId]
}

credential_not_suspended if {
    agent_state := data.arhia.agents[input.credential.agentId].state
    agent_state != "SUSPENDED"
}

credential_valid if {
    credential_schema_valid
    credential_not_expired
    credential_lifetime_valid
    credential_hmac_valid
    credential_not_revoked
    credential_not_suspended
}

# ─── Permission Check ───
has_permission(action) if {
    credential_valid
    action in input.credential.permissionSet
}

has_permission(action) if {
    credential_valid
    "*" in input.credential.permissionSet
    not action in data.arhia.aim.restrictedActions
}

# ─── 4-Layer Composite Identity Chain (AIM-C02) ───
agent_layer_valid if {
    input.credential.agentId
    data.arhia.agents[input.credential.agentId]
}

supervisor_layer_valid if {
    input.credential.supervisorId
    supervisor := data.arhia.personnel[input.credential.supervisorId]
    supervisor.active == true
}

department_layer_valid if {
    input.credential.departmentScope
    dept := data.arhia.departments[input.credential.departmentScope]
    dept.active == true
}

auth_boundary_valid if {
    dept := data.arhia.departments[input.credential.departmentScope]
    boundary := dept.authorizationBoundary
    every perm in input.credential.permissionSet {
        perm in boundary.allowedActions
    }
}

identity_chain_complete if {
    agent_layer_valid
    supervisor_layer_valid
    department_layer_valid
    auth_boundary_valid
}

chain_resolution := {
    "agent": input.credential.agentId,
    "supervisor": input.credential.supervisorId,
    "department": input.credential.departmentScope,
    "authBoundary": data.arhia.departments[input.credential.departmentScope].authorizationBoundary.name,
    "chainComplete": identity_chain_complete,
}

# ─── Scope Attenuation ───
effective_permissions := perms if {
    identity_chain_complete
    boundary := data.arhia.departments[input.credential.departmentScope].authorizationBoundary
    perms := {p | p := input.credential.permissionSet[_]; p in boundary.allowedActions}
}

effective_permissions := set() if {
    not identity_chain_complete
}

# ─── Evidence ───
evidence := {
    "@type": "ATT",
    "controlId": "AIM-C01",
    "agentId": input.credential.agentId,
    "credentialValid": credential_valid,
    "chainComplete": identity_chain_complete,
    "effectivePermissionCount": count(effective_permissions),
    "retentionTier": "Tier1",
}

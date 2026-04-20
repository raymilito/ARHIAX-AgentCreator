# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B16: AIM Permission & Scope Enforcement (NEW)
# Controls: AIM-C01, AIM-C02
# Lines: ~110
# ═══════════════════════════════════════════════════════════════════
package arhia.aim.permissions

import rego.v1
import data.arhia.aim.identity as identity

# ─── Configuration ───
default action_permitted := false
default scope_valid := false

permission_inheritance := true

# ─── Action Classification ───
action_risk_levels := {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

action_classifications := {
    "read": "LOW",
    "query": "LOW",
    "list": "LOW",
    "analyze": "MEDIUM",
    "suggest": "MEDIUM",
    "execute": "MEDIUM",
    "create": "HIGH",
    "modify": "HIGH",
    "delete": "CRITICAL",
    "deploy": "CRITICAL",
    "transfer_funds": "CRITICAL",
    "modify_policy": "CRITICAL",
    "promote_agent": "CRITICAL",
    "override_safety": "CRITICAL",
}

action_risk(action) := level if {
    level := action_classifications[action]
}

action_risk(action) := "HIGH" if {
    not action_classifications[action]
}

# ─── Direct Permission Check ───
directly_permitted(action) if {
    identity.credential_valid
    action in input.credential.permissionSet
}

# ─── Wildcard Permission ───
wildcard_permitted(action) if {
    identity.credential_valid
    "*" in input.credential.permissionSet
    risk := action_risk(action)
    action_risk_levels[risk] < action_risk_levels["CRITICAL"]
}

wildcard_critical_requires_explicit if {
    "*" in input.credential.permissionSet
    risk := action_risk(input.request.action)
    action_risk_levels[risk] >= action_risk_levels["CRITICAL"]
    not input.request.action in input.credential.permissionSet
}

# ─── Inherited Permission (from supervisor) ───
inherited_permitted(action) if {
    permission_inheritance
    supervisor_id := input.credential.supervisorId
    supervisor_perms := data.arhia.personnel[supervisor_id].delegatedPermissions
    action in supervisor_perms
}

# ─── Department Scope Enforcement ───
scope_valid if {
    dept := input.credential.departmentScope
    department := data.arhia.departments[dept]
    department.active == true
    boundary := department.authorizationBoundary
    input.request.resource in boundary.allowedResources
}

scope_valid if {
    dept := input.credential.departmentScope
    department := data.arhia.departments[dept]
    department.active == true
    boundary := department.authorizationBoundary
    "*" in boundary.allowedResources
}

resource_in_scope if {
    scope_valid
}

# ─── Cross-Department Access ───
cross_department_access if {
    input.request.targetDepartment
    input.request.targetDepartment != input.credential.departmentScope
}

cross_department_permitted if {
    cross_department_access
    bridge := data.arhia.aim.departmentBridges[input.credential.departmentScope]
    input.request.targetDepartment in bridge.allowedTargets
    input.request.action in bridge.allowedActions
}

cross_department_denied if {
    cross_department_access
    not cross_department_permitted
}

# ─── Temporal Scope ───
within_operating_hours if {
    not data.arhia.agents[input.credential.agentId].operatingHours
}

within_operating_hours if {
    hours := data.arhia.agents[input.credential.agentId].operatingHours
    input.context.hour >= hours.start
    input.context.hour < hours.end
}

# ─── Composite Permission Decision ───
action_permitted if {
    directly_permitted(input.request.action)
    resource_in_scope
    within_operating_hours
    not cross_department_denied
}

action_permitted if {
    wildcard_permitted(input.request.action)
    resource_in_scope
    within_operating_hours
    not cross_department_denied
}

action_permitted if {
    inherited_permitted(input.request.action)
    resource_in_scope
    within_operating_hours
    not cross_department_denied
}

# ─── Denial Reasons ───
denial_reasons := reasons if {
    reasons := {reason |
        not identity.credential_valid; reason := "INVALID_CREDENTIAL"
    } | {reason |
        not directly_permitted(input.request.action)
        not wildcard_permitted(input.request.action)
        not inherited_permitted(input.request.action)
        reason := "NO_PERMISSION"
    } | {reason |
        not resource_in_scope; reason := "OUT_OF_SCOPE"
    } | {reason |
        not within_operating_hours; reason := "OUTSIDE_HOURS"
    } | {reason |
        cross_department_denied; reason := "CROSS_DEPT_DENIED"
    } | {reason |
        wildcard_critical_requires_explicit; reason := "CRITICAL_NEEDS_EXPLICIT"
    }
}

# ─── Evidence ───
evidence := {
    "@type": "ATT",
    "controlId": "AIM-C02",
    "agentId": input.credential.agentId,
    "action": input.request.action,
    "actionRisk": action_risk(input.request.action),
    "permitted": action_permitted,
    "denialReasons": denial_reasons,
    "retentionTier": "Tier2",
}

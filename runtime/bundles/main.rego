package arhiax.main

# Política base del Gateway ARHIAX — §13 del doc de arquitectura.
#
# Evalúa cinco gates de negocio por encima de la validez del token:
#   1. inyección             (rechaza con INJECTION_DETECTED)
#   2. ownership             (subject == resource_owner o resource_id ∈ principal_scopes)
#   3. estado del flujo      (case_state ∈ allowed_case_states)
#   4. autonomy vs severity  (A0..A4 contra acciones high/critical)
#   5. step-up / dual approval para HIGH / CRITICAL
#
# Salidas:
#   allow         bool
#   reasons       []string   códigos legibles para auditoría
#   obligations   []object   obligaciones runtime (rate_limit, audit_log)
#   outcome       string     ALLOW | ALLOW_WITH_HIC_NOTIFICATION |
#                            ESCALATE_TO_HUMAN | DENY | DENY_WITH_INCIDENT

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default allow := false
default obligations := []

# ── Helpers de contexto ─────────────────────────────────────────────────────

autonomy_level := lvl if {
    lvl := input.context.requestedAutonomyLevel
} else := "A0"

severity := sev if {
    sev := upper(input.context.severity)
} else := "MEDIUM"

# ── Inyección ───────────────────────────────────────────────────────────────

injection_patterns := [
    "ignore previous",
    "disregard",
    "<script>",
    "drop table",
    "union select",
    "javascript:",
]

is_injection if {
    msg := lower(sprintf("%v", [input.context]))
    some p
    contains(msg, injection_patterns[p])
}

# ── Operación válida ────────────────────────────────────────────────────────

valid_actions := {
    "toolCall", "modelInvoke", "dataAccess", "interAgentCall",
    "read", "write", "query", "notify",
}

is_valid_operation_type if {
    input.action in valid_actions
}

# ── Ownership ───────────────────────────────────────────────────────────────
# Se activa solo si el contexto trae resource_owner o principal_scopes.
# Sin esos campos se considera satisfecho (back-compat con clientes simples).

has_ownership_check if { input.context.resource_owner }
has_ownership_check if { input.context.principal_scopes }

required_resource_id := id if {
    id := input.context.case_id
} else := id if {
    id := input.context.resource_id
} else := ""

ownership_satisfied if { not has_ownership_check }

ownership_satisfied if {
    input.context.resource_owner == input.subject
}

ownership_satisfied if {
    required_resource_id != ""
    required_resource_id in input.context.principal_scopes
}

# ── Estado del flujo ────────────────────────────────────────────────────────

default_open_states := {"OPEN", "IN_REVIEW", "ACTIVE"}

case_state_ok if { not input.context.case_state }

case_state_ok if {
    input.context.case_state
    allowed := input.context.allowed_case_states
    input.context.case_state in allowed
}

case_state_ok if {
    input.context.case_state
    not input.context.allowed_case_states
    input.context.case_state in default_open_states
}

# ── Severity y autonomy ─────────────────────────────────────────────────────
# La severidad se declara explicitamente en el contexto (@governed_tool envia
# `severity` desde el SDK). Acciones sensibles a nivel de negocio se modelan
# fijando severity="HIGH"|"CRITICAL" en el decorador, no por nombre de accion.

is_critical if { severity == "CRITICAL" }
is_high if { severity == "HIGH" }

step_up_satisfied if { input.context.step_up_satisfied == true }
dual_approval_satisfied if { input.context.dual_approval_ticket_id }

# Reglas de autonomía:
#   A4 → todo
#   A3 → todo excepto critical
#   A2 → no critical sin dual approval; high requiere step-up
#   A1 → no critical; high requiere step-up
#   A0 → solo lecturas sin severity

autonomy_permits if { autonomy_level == "A4" }

autonomy_permits if {
    autonomy_level == "A3"
    not is_critical
}

autonomy_permits if {
    autonomy_level in {"A1", "A2"}
    is_high
    not is_critical
    step_up_satisfied
}

autonomy_permits if {
    autonomy_level == "A2"
    is_critical
    step_up_satisfied
    dual_approval_satisfied
}

autonomy_permits if {
    autonomy_level in {"A0", "A1", "A2"}
    not is_high
    not is_critical
}

# ── Decisión ────────────────────────────────────────────────────────────────

allow if {
    not is_injection
    is_valid_operation_type
    ownership_satisfied
    case_state_ok
    autonomy_permits
}

# ── Outcome ─────────────────────────────────────────────────────────────────
# Cascada exclusiva para evitar conflictos.

outcome := "DENY_WITH_INCIDENT" if {
    is_injection
}

else := "ESCALATE_TO_HUMAN" if {
    not allow
    is_valid_operation_type
    ownership_satisfied
    case_state_ok
    is_critical
    not dual_approval_satisfied
}

else := "ESCALATE_TO_HUMAN" if {
    not allow
    is_valid_operation_type
    ownership_satisfied
    case_state_ok
    is_high
    not is_critical
    not step_up_satisfied
}

else := "ALLOW_WITH_HIC_NOTIFICATION" if {
    allow
    is_high
}

else := "ALLOW" if {
    allow
}

else := "DENY"

# ── Razones ─────────────────────────────────────────────────────────────────

reasons_set contains "INJECTION_DETECTED" if { is_injection }

reasons_set contains "INVALID_OPERATION_TYPE" if {
    not is_injection
    not is_valid_operation_type
}

reasons_set contains "OWNERSHIP_DENIED" if {
    not is_injection
    is_valid_operation_type
    not ownership_satisfied
}

reasons_set contains "INVALID_CASE_STATE" if {
    not is_injection
    is_valid_operation_type
    ownership_satisfied
    not case_state_ok
}

reasons_set contains "STEP_UP_REQUIRED" if {
    not is_injection
    is_valid_operation_type
    ownership_satisfied
    case_state_ok
    is_high
    not is_critical
    not step_up_satisfied
}

reasons_set contains "DUAL_APPROVAL_REQUIRED" if {
    not is_injection
    is_valid_operation_type
    ownership_satisfied
    case_state_ok
    is_critical
    not dual_approval_satisfied
}

reasons_set contains "AUTONOMY_INSUFFICIENT" if {
    not is_injection
    is_valid_operation_type
    ownership_satisfied
    case_state_ok
    not autonomy_permits
    not is_high
    not is_critical
}

reasons := [r | r := reasons_set[_]]

# ── Obligations ─────────────────────────────────────────────────────────────

obligations := [{"type": "audit_log", "value": "high_impact"}] if {
    allow
    is_high
}

obligations := [{"type": "rate_limit", "value": 100}] if {
    allow
    not is_high
}

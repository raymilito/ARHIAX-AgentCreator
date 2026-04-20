package arhiax.main

# Política base ARHIAX — deny-by-default con reglas explícitas de permiso.
# Esta es la política del Gateway. El motor OPA evalúa esto para cada solicitud.

import future.keywords.if
import future.keywords.in

default allow := false
default reasons := []
default obligations := []

# ── Regla principal ──────────────────────────────────────────────────────────

allow if {
    not is_injection
    is_valid_operation_type
    is_permitted_for_level
}

# ── Validaciones ─────────────────────────────────────────────────────────────

is_valid_operation_type if {
    input.action in {"toolCall", "modelInvoke", "dataAccess", "interAgentCall"}
}

is_valid_operation_type if {
    input.action in {"read", "write", "query", "notify"}
}

# ── Detección de inyección ───────────────────────────────────────────────────

injection_patterns := [
    "ignore previous",
    "disregard",
    "<script>",
    "drop table",
    "union select",
    "javascript:",
]

is_injection if {
    prompt := lower(concat("", [
        input.context.input.prompt,
    ]))
    pattern := injection_patterns[_]
    contains(prompt, pattern)
}

# ── Permisos por nivel de autonomía ─────────────────────────────────────────

autonomy_level := input.context.requestedAutonomyLevel if {
    input.context.requestedAutonomyLevel
} else := "A0"

is_permitted_for_level if {
    autonomy_level == "A4"
}

is_permitted_for_level if {
    autonomy_level == "A3"
    not is_critical_action
}

is_permitted_for_level if {
    autonomy_level in {"A0", "A1", "A2"}
    not is_high_impact_action
}

is_permitted_for_level if {
    autonomy_level in {"A0", "A1", "A2"}
    is_high_impact_action
}

# Acciones de alto impacto — generan HIC notification pero se permiten
high_impact_actions := {
    "delete", "transfer_funds", "modify_policy",
    "promote_agent", "revoke_credential", "deploy",
    "override_safety", "grant_permission", "external_api_write",
}

critical_actions := {"override_safety", "revoke_credential", "modify_policy"}

is_high_impact_action if {
    input.action in high_impact_actions
}

is_critical_action if {
    input.action in critical_actions
}

# ── Razones en caso de denegación ───────────────────────────────────────────

reasons := ["INJECTION_DETECTED"] if {
    is_injection
}

reasons := ["INVALID_OPERATION_TYPE"] if {
    not is_valid_operation_type
    not is_injection
}

reasons := ["AUTONOMY_INSUFFICIENT_FOR_CRITICAL_ACTION"] if {
    is_valid_operation_type
    is_critical_action
    autonomy_level in {"A0", "A1", "A2", "A3"}
    not is_injection
}

# ── Obligations ──────────────────────────────────────────────────────────────

obligations := [{"type": "audit_log", "value": "high_impact"}] if {
    allow
    is_high_impact_action
}

obligations := [{"type": "rate_limit", "value": 100}] if {
    allow
    not is_high_impact_action
}

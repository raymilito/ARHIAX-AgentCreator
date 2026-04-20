# =============================================================================
# ARHIAX CE - Main decision entry point
# =============================================================================
# This is the default decision resolved by OPA when the gateway calls
# POST /v1/data without an explicit path. See opa-configmap.yaml:
#   default_decision: /arhiax/main/allow
#
# The gateway sends an input document shaped like:
#   {
#     "subject":   { "id": "agent-1", "roles": ["planner"], "jwt_aud": "arhiax" },
#     "action":    { "verb": "invoke", "tool": "web.fetch" },
#     "resource":  { "type": "external_api", "uri": "https://example.com" },
#     "context":   { "tenant": "acme", "env": "prod", "trace_id": "..." }
#   }
#
# The response shape is:
#   { "allow": bool, "reasons": [...], "obligations": [...] }
# =============================================================================
package arhiax.main

import rego.v1

default allow := false

# -----------------------------------------------------------------------------
# Top-level decision: allow if no hard denial AND at least one permit fires.
# -----------------------------------------------------------------------------
allow if {
    not hard_deny
    permit
}

# -----------------------------------------------------------------------------
# Hard denials - any of these short-circuits the decision to false.
# -----------------------------------------------------------------------------
hard_deny if {
    data.arhiax.decisions.jwt_audience_invalid
}

hard_deny if {
    data.arhiax.decisions.tool_blocklisted
}

hard_deny if {
    data.arhiax.decisions.tenant_suspended
}

# -----------------------------------------------------------------------------
# Permit rules - at least one must hold.
# -----------------------------------------------------------------------------
permit if {
    data.arhiax.decisions.subject_has_required_role
}

permit if {
    data.arhiax.decisions.read_only_action
}

# -----------------------------------------------------------------------------
# Reasons - explain the decision back to the gateway for evidence logging.
# -----------------------------------------------------------------------------
reasons contains reason if {
    data.arhiax.decisions.jwt_audience_invalid
    reason := "jwt_audience_invalid"
}

reasons contains reason if {
    data.arhiax.decisions.tool_blocklisted
    reason := sprintf("tool_blocklisted: %s", [input.action.tool])
}

reasons contains reason if {
    data.arhiax.decisions.tenant_suspended
    reason := sprintf("tenant_suspended: %s", [input.context.tenant])
}

reasons contains reason if {
    allow
    reason := "permitted"
}

# -----------------------------------------------------------------------------
# Obligations - side-effects the gateway MUST enforce if allow=true.
# -----------------------------------------------------------------------------
obligations contains obligation if {
    allow
    input.action.verb == "invoke"
    obligation := {
        "type": "rate_limit",
        "key":  sprintf("%s:%s", [input.context.tenant, input.subject.id]),
        "rps":  10,
    }
}

obligations contains obligation if {
    allow
    input.context.env == "prod"
    obligation := {
        "type": "audit_log",
        "level": "info",
    }
}

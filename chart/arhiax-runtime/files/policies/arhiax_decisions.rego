# =============================================================================
# ARHIAX CE - Atomic decision predicates
# =============================================================================
# These are the leaf rules consumed by main.rego. Each rule evaluates to
# true/false based purely on the input document. No side effects, no
# cross-rule dependencies inside this file.
# =============================================================================
package arhiax.decisions

import rego.v1

# -----------------------------------------------------------------------------
# JWT audience validation.
# The gateway is configured with accepted audiences via ARHIAX_JWT_AUDIENCES.
# The gateway echoes the validated audience into input.subject.jwt_aud.
# -----------------------------------------------------------------------------
jwt_audience_invalid if {
    not input.subject.jwt_aud
}

jwt_audience_invalid if {
    input.subject.jwt_aud == ""
}

# -----------------------------------------------------------------------------
# Tool blocklist.
# A minimal blocklist of tools that are never permitted in CE. Extend or
# override via a separate policy file in the bundle.
# -----------------------------------------------------------------------------
blocked_tools := {
    "system.exec",
    "system.shell",
    "fs.write_arbitrary",
    "network.raw_socket",
}

tool_blocklisted if {
    input.action.tool in blocked_tools
}

# -----------------------------------------------------------------------------
# Tenant suspension.
# Hardcoded empty set in CE; enterprise builds wire this to a data document
# refreshed from the evidence store.
# -----------------------------------------------------------------------------
suspended_tenants := set()

tenant_suspended if {
    input.context.tenant in suspended_tenants
}

# -----------------------------------------------------------------------------
# Role-based permit: subject has at least one role from the required set.
# -----------------------------------------------------------------------------
required_roles := {"planner", "executor", "reviewer"}

subject_has_required_role if {
    some role in input.subject.roles
    role in required_roles
}

# -----------------------------------------------------------------------------
# Read-only action permit: verbs that never mutate state are always allowed
# for authenticated subjects, regardless of role.
# -----------------------------------------------------------------------------
read_only_verbs := {"get", "list", "describe", "head"}

read_only_action if {
    input.action.verb in read_only_verbs
    input.subject.jwt_aud != ""
}

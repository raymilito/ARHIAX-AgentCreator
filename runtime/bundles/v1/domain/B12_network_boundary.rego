# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B12: Network Boundary Enforcement
# Agent network segmentation and egress control
# Lines: ~70
# ═══════════════════════════════════════════════════════════════════
package arhia.domain.network_boundary

import rego.v1

default network_access_allowed := false

allowed_protocols := {"HTTPS", "gRPC", "WSS"}

egress_allowed if {
    input.network.protocol in allowed_protocols
    domain := input.network.targetDomain
    allowlist := data.arhia.agents[input.network.agentId].allowedDomains
    domain in allowlist
}

egress_allowed if {
    input.network.protocol in allowed_protocols
    input.network.targetType == "INTERNAL"
}

internal_only_agent if {
    data.arhia.agents[input.network.agentId].networkPolicy == "INTERNAL_ONLY"
}

external_blocked if {
    internal_only_agent
    input.network.targetType == "EXTERNAL"
}

rate_limit_ok if {
    input.metrics.requestsPerMinute <= 1000
}

network_access_allowed if {
    egress_allowed
    not external_blocked
    rate_limit_ok
}

evidence := {
    "@type": "LOG",
    "controlId": "B12",
    "agentId": input.network.agentId,
    "targetDomain": input.network.targetDomain,
    "allowed": network_access_allowed,
    "retentionTier": "Tier2",
}

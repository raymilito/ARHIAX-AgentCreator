# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B08: Output Filtering & Sanitization
# OWASP ASI-07 defense layer
# Lines: ~70
# ═══════════════════════════════════════════════════════════════════
package arhia.domain.output_filter

import rego.v1

default output_safe := false

pii_patterns := ["SSN", "credit_card", "passport", "bank_account", "cpf", "rfc", "curp"]

sensitive_data_leaked if {
    pattern := pii_patterns[_]
    contains(lower(json.marshal(input.output)), lower(pattern))
}

hallucination_markers := ["as an AI", "I cannot", "I don't have access"]

potential_hallucination if {
    marker := hallucination_markers[_]
    contains(input.output.content, marker)
    input.output.confidenceScore < 0.7
}

output_format_valid if {
    input.output.format in {"JSON", "TEXT", "HTML", "MARKDOWN"}
    count(input.output.content) > 0
    count(input.output.content) < 1048576
}

output_safe if {
    output_format_valid
    not sensitive_data_leaked
}

evidence := {
    "@type": "LOG",
    "controlId": "B08",
    "outputSafe": output_safe,
    "piiDetected": sensitive_data_leaked,
    "retentionTier": "Tier2",
}

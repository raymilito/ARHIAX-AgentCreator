# ARHIA v11.5 — C09 INTERP Bridge
# Policy: interp.rego v0.1
#
# This file is the canonical OPA Rego policy stub for C09.
# The full policy bundle is documented in:
#   specs/v11.5/ARHIA_v11.5_interp.rego.docx
#
# For the Python reference implementation port, see:
#   arhia_c09/gate.py  (DivergenceGate — Python port of this policy)
#
# Production deployments call OPA directly with this bundle.
# The Python port exists so the test harness can run without an OPA binary.

package arhia.c09.interp

import future.keywords.if
import future.keywords.in

# ── Configuration (from data.arhia.c09.config) ─────────────────────────────

default tau_div_general       := 0.65
default tau_div_regulated     := 0.40
default max_signal_age_sec    := 300
default min_impact_class      := 3
default fail_closed_on_missing := false

regulated_sectors := {"health", "finance", "critical_infrastructure"}

tau_div := data.arhia.c09.config.tau_div_regulated if {
    data.arhia.c09.config.deployment.sector in regulated_sectors
} else := data.arhia.c09.config.tau_div_general

# ── Main decision ───────────────────────────────────────────────────────────

# force_hil: divergence confirmed + impact class meets gate threshold
decision := "force_hil" if {
    input.envelope != null
    signal_admissible
    input.envelope.class == "C"
    lb := behavioral_divergence_lower_bound
    lb > tau_div
    input.action.impact_class >= min_impact_class
}

# log_only: signal inadmissible
decision := "log_only" if {
    input.envelope != null
    not signal_admissible
}

# no_signal + fail_closed
decision := "force_hil" if {
    input.envelope == null
    fail_closed_on_missing
    input.action.impact_class >= 4
    data.arhia.c09.config.deployment.sector in regulated_sectors
}

# default: weighted or no_signal
default decision := "no_signal"

# ── Admissibility ───────────────────────────────────────────────────────────

signal_admissible if {
    count(inadmissibility_reasons) == 0
}

inadmissibility_reasons[reason] if {
    producer := data.arhia.c09.cir[input.envelope.producer]
    producer.status != "active"
    reason := "producer_not_accredited"
}

inadmissibility_reasons["producer_not_accredited"] if {
    not data.arhia.c09.cir[input.envelope.producer]
}

inadmissibility_reasons["signal_stale"] if {
    produced := time.parse_rfc3339_ns(input.envelope.produced_at)
    now := time.now_ns()
    (now - produced) > (max_signal_age_sec * 1000000000)
}

# ── Class C helpers ─────────────────────────────────────────────────────────

behavioral_divergence_lower_bound := lb if {
    some concept in input.envelope.concepts
    concept.name == "behavioral_divergence"
    lb := concept.ci_95[0]
}

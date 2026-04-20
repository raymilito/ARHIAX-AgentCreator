# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B18: EGA Evidence Validation (NEW)
# Controls: EGA-C01, EGA-C02, EGA-C04
# Lines: ~85
# ═══════════════════════════════════════════════════════════════════
package arhia.ega.evidence

import rego.v1

# ─── Configuration ───
default evidence_valid := false

valid_evidence_types := {"LOG", "ATT", "MET", "APR", "TST"}

required_envelope_fields := [
    "@context", "@type", "controlId", "agentId",
    "timestamp", "payload", "hmacChain", "retentionTier"
]

valid_retention_tiers := {"Tier1", "Tier2", "Tier3"}

context_uri := "https://arhia.sinergia.co/schema/evidence/v11.4"

# ─── Evidence Envelope Standard (EGA-C01) ───
envelope_schema_valid if {
    every field in required_envelope_fields {
        input.evidence[field]
    }
    input.evidence["@context"] == context_uri
    input.evidence["@type"] in valid_evidence_types
    is_string(input.evidence.controlId)
    is_string(input.evidence.agentId)
    is_number(input.evidence.timestamp)
    input.evidence.retentionTier in valid_retention_tiers
}

envelope_hmac_valid if {
    input.evidence.hmacChain
    is_string(input.evidence.hmacChain)
    count(input.evidence.hmacChain) >= 64
}

envelope_timestamp_valid if {
    input.evidence.timestamp > 0
    input.evidence.timestamp <= input.context.currentTime + 60
}

# ─── Evidence Type Classification (EGA-C02) ───
type_schema_valid if {
    input.evidence["@type"] == "LOG"
    input.evidence.payload.eventType
    input.evidence.payload.eventData
}

type_schema_valid if {
    input.evidence["@type"] == "ATT"
    input.evidence.payload.attestationType
    input.evidence.payload.attestationResult
    input.evidence.payload.verificationMethod
}

type_schema_valid if {
    input.evidence["@type"] == "MET"
    input.evidence.payload.metricName
    input.evidence.payload.metricValue
    is_number(input.evidence.payload.metricValue)
    input.evidence.payload.unit
}

type_schema_valid if {
    input.evidence["@type"] == "APR"
    input.evidence.payload.signerId
    input.evidence.payload.decision
    input.evidence.payload.decision in {"APPROVED", "DENIED", "DEFERRED"}
}

type_schema_valid if {
    input.evidence["@type"] == "TST"
    input.evidence.payload.testId
    input.evidence.payload.testResult
    input.evidence.payload.testResult in {"PASS", "FAIL", "SKIP", "ERROR"}
}

# ─── Evidence Completeness Monitoring (EGA-C04) ───
control_evidence_requirements := data.arhia.ega.controlEvidenceMap

control_evidence_complete(control_id) if {
    required := control_evidence_requirements[control_id]
    produced := data.arhia.ega.producedEvidence[control_id]
    every req_type in required {
        req_type in produced
    }
}

incomplete_controls := controls if {
    controls := {cid |
        some cid
        required := control_evidence_requirements[cid]
        not control_evidence_complete(cid)
    }
}

completeness_score := score if {
    total := count(control_evidence_requirements)
    complete := total - count(incomplete_controls)
    score := complete / total
}

completeness_alert if {
    completeness_score < 1.0
}

# ─── Composite Validation ───
evidence_valid if {
    envelope_schema_valid
    envelope_hmac_valid
    envelope_timestamp_valid
    type_schema_valid
}

validation_errors := errors if {
    errors := {err |
        not envelope_schema_valid; err := "INVALID_ENVELOPE"
    } | {err |
        not envelope_hmac_valid; err := "INVALID_HMAC"
    } | {err |
        not envelope_timestamp_valid; err := "INVALID_TIMESTAMP"
    } | {err |
        not type_schema_valid; err := "INVALID_TYPE_SCHEMA"
    }
}

# ─── Evidence (meta-evidence) ───
meta_evidence := {
    "@type": "LOG",
    "controlId": "EGA-C01",
    "validationResult": evidence_valid,
    "errors": validation_errors,
    "completenessScore": completeness_score,
    "retentionTier": "Tier2",
}

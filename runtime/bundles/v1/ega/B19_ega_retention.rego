# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B19: EGA Retention Enforcement (NEW)
# Controls: EGA-C03
# Lines: ~70
# ═══════════════════════════════════════════════════════════════════
package arhia.ega.retention

import rego.v1

# ─── Retention Tier Definitions ───
retention_tiers := {
    "Tier1": {"years": 7, "days": 2555, "scope": "safety_critical",
              "description": "Safety-critical, regulatory compliance, audit evidence"},
    "Tier2": {"years": 3, "days": 1095, "scope": "security",
              "description": "Security events, operational decisions, policy evaluations"},
    "Tier3": {"years": 1, "days": 365, "scope": "routine",
              "description": "Routine telemetry, periodic baselines, informational logs"},
}

# ─── Control → Tier Mapping ───
control_tier_overrides := {
    "ATK-C01": "Tier1", "ATK-C05": "Tier1", "ATK-C06": "Tier1", "ATK-C07": "Tier1",
    "AIM-C01": "Tier1", "AIM-C02": "Tier1", "AIM-C03": "Tier1",
    "ABO-C02": "Tier1", "ABO-C03": "Tier1",
    "AUT-C02": "Tier1", "AUT-C03": "Tier1",
    "HIC-C01": "Tier1", "HIC-C03": "Tier1",
    "EGA-C01": "Tier1",
}

required_tier(control_id) := tier if {
    tier := control_tier_overrides[control_id]
}

required_tier(control_id) := "Tier2" if {
    not control_tier_overrides[control_id]
}

# ─── Tier Validation ───
default retention_compliant := false

tier_valid if {
    input.evidence.retentionTier in {"Tier1", "Tier2", "Tier3"}
}

tier_meets_minimum if {
    required := required_tier(input.evidence.controlId)
    actual := input.evidence.retentionTier
    retention_tiers[actual].days >= retention_tiers[required].days
}

tier_downgrade_detected if {
    tier_valid
    not tier_meets_minimum
}

# ─── Expiration Check ───
evidence_age_days := age if {
    age := (input.context.currentTime - input.evidence.timestamp) / 86400
}

evidence_expired if {
    tier := input.evidence.retentionTier
    max_days := retention_tiers[tier].days
    evidence_age_days > max_days
}

evidence_approaching_expiry if {
    tier := input.evidence.retentionTier
    max_days := retention_tiers[tier].days
    remaining := max_days - evidence_age_days
    remaining <= 30
    remaining > 0
}

# ─── Legal Hold ───
under_legal_hold if {
    data.arhia.ega.legalHolds[input.evidence.controlId]
}

deletion_blocked if {
    under_legal_hold
}

deletion_blocked if {
    not evidence_expired
}

deletion_allowed if {
    evidence_expired
    not under_legal_hold
}

# ─── Retention Compliance ───
retention_compliant if {
    tier_valid
    tier_meets_minimum
    not tier_downgrade_detected
}

compliance_issues := issues if {
    issues := {issue |
        not tier_valid; issue := "INVALID_TIER"
    } | {issue |
        tier_downgrade_detected; issue := "TIER_DOWNGRADE"
    } | {issue |
        evidence_expired; issue := "EXPIRED"
    }
}

# ─── Evidence ───
evidence := {
    "@type": "LOG",
    "controlId": "EGA-C03",
    "evidenceControlId": input.evidence.controlId,
    "assignedTier": input.evidence.retentionTier,
    "requiredTier": required_tier(input.evidence.controlId),
    "compliant": retention_compliant,
    "ageDays": evidence_age_days,
    "expired": evidence_expired,
    "legalHold": under_legal_hold,
    "retentionTier": "Tier2",
}

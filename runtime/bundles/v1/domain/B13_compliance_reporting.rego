# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B13: Compliance & Regulatory Reporting
# Automated compliance evidence aggregation
# Lines: ~65
# ═══════════════════════════════════════════════════════════════════
package arhia.domain.compliance_reporting

import rego.v1

default compliance_check_pass := false

required_frameworks := {"ARISE", "OWASP", "CSA_ATF", "MGF", "NIST_CSF"}

framework_coverage_met(fw) if {
    coverage := data.arhia.compliance.frameworkCoverage[fw]
    coverage.percentComplete >= 80.0
}

all_frameworks_covered if {
    every fw in required_frameworks {
        framework_coverage_met(fw)
    }
}

active_findings := findings if {
    findings := {f |
        some f
        finding := data.arhia.compliance.findings[f]
        finding.status == "OPEN"
    }
}

critical_findings := findings if {
    findings := {f |
        some f
        finding := data.arhia.compliance.findings[f]
        finding.status == "OPEN"
        finding.severity == "CRITICAL"
    }
}

compliance_check_pass if {
    all_frameworks_covered
    count(critical_findings) == 0
}

report_payload := {
    "frameworksCovered": required_frameworks,
    "allCovered": all_frameworks_covered,
    "openFindings": count(active_findings),
    "criticalFindings": count(critical_findings),
    "compliancePass": compliance_check_pass,
}

evidence := {
    "@type": "MET",
    "controlId": "B13",
    "compliancePass": compliance_check_pass,
    "report": report_payload,
    "retentionTier": "Tier1",
}

# ADR Patch Note — v0.1.0-marketing-preview

**Date:** 2026-04-12
**Applies to:** `ARHIA_v11.5_C09_ADRs_v0.1.md` (ADR-C09-001, ADR-C09-002, ADR-C09-003)

---

## Purpose

This patch note resolves a referential gap identified during the v0.1.0 reproducibility audit: the three ADRs reference *"Open Questions 1–4 in the C09 spec document"*, but no separate technical spec document by that name exists in this repository. The narrative spec `ARHIA_v11.5_C09_INTERP_Bridge_Spec_v0.1.docx` covers architecture, evidence classes, controls, and roadmap, but does **not** contain the byte-level INTERP-EV format, the producer accreditation rules, the precise A/B/C class semantics, or the emergency revocation protocol at the level of detail the ADRs assume.

## Resolution for v0.1.0-marketing-preview

The four Open Questions referenced in the ADRs are **deferred to spec v0.2** and are explicitly **out of scope for the v0.1.0 reference implementation**. They are:

1. **OQ-1:** Byte-level canonical encoding of `INTERP-EV/1.0` (currently defined only at JSON Schema level).
2. **OQ-2:** Producer accreditation procedure (currently stub: a producer is "accredited" if it appears in the local CIR with `revoked=false`).
3. **OQ-3:** Formal semantics distinguishing Class A, B, and C evidence under composition (currently described informally).
4. **OQ-4:** Multi-party emergency revocation protocol with 2-of-3 signers (currently a placeholder; **no real signatories are designated, and none are required for the v0.1.0 marketing preview**).

## Status of ADR-C09-002 emergency signatories

ADR-C09-002 states that *"before proceeding to production deployment, designate the 3 emergency revocation signatories and publish their public keys."*

**For v0.1.0-marketing-preview, this requirement is NOT a blocker**, because the v0.1.0 release is explicitly **not for production deployment**. The signatory designation is correctly scoped as a Phase 2 prerequisite, and Phase 2 is open to research collaboration and not part of Sinergia's 2026 commercial roadmap (see README).

Any future production deployment under Phase 2 must complete OQ-4 and designate signatories before going live. This patch note does not weaken that requirement; it clarifies that the requirement applies to Phase 2, not to v0.1.0.

## Effect on Phase 1 exit criteria

The Phase 1+ exit criteria (FPR 0/100, TPR 100/100, ledger HMAC integrity, end-to-end reproducibility) are **unaffected** by this patch note. They were and remain PASS under v0.1.0.

The earlier wording in the closing summary — *"Phase 1+ status: PASS in 4 exit criteria"* — should be read as: PASS for the four **technical** exit criteria of the reference implementation, not as a statement that all organizational prerequisites for production deployment have been met. The two are explicitly separated as of this patch.

---

*Sinergia Consulting Group S.A.S. — 2026-04-12.*

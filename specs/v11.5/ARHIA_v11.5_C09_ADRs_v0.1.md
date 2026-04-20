# ARHIA v11.5 — C09 Architecture Decision Records (Phase 0)

**Owner:** Sinergia Consulting Group S.A.S.
**Status:** Phase 0 freeze, v0.1
**Date:** 2026-04-12
**Scope:** Three contested design decisions in the INTERP Bridge that require explicit justification before Phase 1 implementation.

---

## ADR-C09-001 — Default value of τ_div (divergence threshold)

### Context

The divergence gate (INT-C02) compares the lower bound of the 95% confidence interval of a Class C `behavioral_divergence` signal against a threshold τ_div. If the lower bound exceeds τ_div and the action's impact class is ≥ 3, the gate forces `require_HIL`. The threshold value materially determines the false-positive vs false-negative tradeoff and therefore the operational cost of C09 to deployers.

Setting τ_div too low produces excessive HIL escalations on benign actions, eroding operator trust and incentivizing deployers to disable C09. Setting it too high produces silent passes on the exact cases C09 exists to catch — including the canonical Mythos `no_macro_used` case, where the divergence is large but not maximal.

### Decision

Two default thresholds, selected at runtime by deployment sector:

- **τ_div_general = 0.65** for general production deployments.
- **τ_div_regulated = 0.40** for regulated sectors (health, finance, critical infrastructure).

Both values are configurable per deployment. The defaults represent the v0.1 starting point and will be re-tuned against false-positive rates measured during Phase 1 reference implementation testing.

### Rationale

The 0.65 general default sits above the midpoint of the [0,1] range, reflecting the operational reality that most agent steps in production are compliant and that operators will not tolerate frequent HIL interruptions. A signal with lower bound > 0.65 is one where the producer is confident — accounting for uncertainty — that more than two-thirds of the divergence "weight" is real. This is a strong signal by construction.

The 0.40 regulated default is asymmetric on purpose. In sectors where the cost of a missed deceptive action is catastrophic (clinical decision support, financial transactions, port logistics, energy infrastructure), the cost-asymmetry justifies tolerating more HIL escalations to reduce false negatives. The 0.40 value is approximately the lowest threshold at which the gate remains semantically meaningful — below 0.40, the lower bound is consistent with random noise from any minimally-trained probe.

Both defaults are conservative in the sense that they will be tightened, not loosened, after Phase 1 calibration. Tightening (raising τ_div) is safe because it produces fewer false positives; loosening would be unsafe because it would silently weaken the gate.

### Consequences

- Phase 1 must produce a false-positive rate measurement on a control set of at least 100 compliant agent traces. If the rate exceeds 5% at the general default, the default is raised before v0.2 freeze.
- Deployers in regulated sectors must explicitly acknowledge the tighter default at deployment time via the `data.arhia.c09.config.deployment.sector` field. Failure to declare the sector causes the general default to apply, which is a known weakness in v0.1 and is tracked in the v0.2 backlog.
- The two-tier model is the simplest defensible structure for v0.1. A continuous calibration model (τ_div as a function of historical false-positive rate per producer) is deferred to v12.0.

---

## ADR-C09-002 — Producer revocation policy

### Context

The Calibrated Interpretability Registry (CIR, INT-C01) accredits interpretability producers and grants their signed envelopes the right to influence policy decisions through the divergence gate and Class A enrichment channels. Accreditation creates an attack surface: a compromised, malicious, or systematically miscalibrated producer can cause C09 to either over-trigger HIL (denial of service against the deployer) or under-trigger it (silent erosion of the safety floor).

Revocation must therefore be both fast enough to limit damage from a discovered failure, and conservative enough that producers can rely on accreditation as a stable commercial property. These goals are in tension.

### Decision

Three-tier revocation with explicit semantics for each tier:

1. **Soft revocation (suspension):** producer entries are flagged `status: "suspended"`. Suspended producers continue to flow into the IEL as passive observability but are excluded from `signal_admissible` and therefore have zero policy influence. Triggered by: missed calibration renewal, three consecutive false-positive incident reports within 30 days, or producer self-request.

2. **Hard revocation:** producer entries are removed from the active CIR and added to a permanent revocation list. Past signals from a hard-revoked producer remain in the IEL with their original ledger entries (immutable history) but are flagged retroactively as "revoked-source" in any forensic reconstruction. Triggered by: signature key compromise, demonstrated systematic deception by the producer, or court order.

3. **Emergency revocation:** out-of-band signed revocation message that propagates to all CIR consumers within five minutes via a publish-subscribe channel. Reserved for active key compromise. Requires signature from at least two of three Sinergia revocation signers in v0.1; transitions to multi-stakeholder council in v0.2.

### Rationale

Soft revocation exists because most failures are operational, not adversarial: a producer misses a calibration renewal, a probe drifts as the target model is updated, a calibration manifest serves stale data. These cases should not destroy the producer's commercial standing — they should temporarily suspend policy influence until the issue is corrected. Soft revocation is reversible without ledger forensics.

Hard revocation exists because some failures are categorical: the signing key is leaked, the producer is shown to have falsified calibration data, a court order requires removal. These cases require permanent removal but must preserve historical ledger integrity, because rewriting the IEL would destroy the audit guarantee that is the entire point of INT-C03.

Emergency revocation exists because key compromise is the one failure mode where minutes matter. Five minutes is the operational target; below this, the revocation channel itself becomes a bottleneck.

The two-of-three signer requirement for emergency revocation is the v0.1 compromise between speed and abuse resistance. A single signer would be too easily compromised; three-of-three would be too slow and would create availability risk. Two-of-three with three named signers gives a reasonable Byzantine tolerance for the bootstrap phase.

### Consequences

- Sinergia must designate the three v0.1 emergency revocation signers and publish their public keys before Phase 1.
- The CIR data model must include `status`, `expires_at`, `calibration_signed_at`, and `revocation_history` fields. The Phase 0 schema work must add these.
- The transition from Sinergia-curated to multi-stakeholder council governance is the single most important v0.2 design item. It is tracked as Open Question 1 in the C09 spec.

---

## ADR-C09-003 — Failure mode when no producer is available

### Context

C09 enriches ATK decisions with internal-state evidence, but for many target models (especially black-box API-mediated frontier models without an accredited Class A producer), no interpretability signal will be available for a given step. The bundle must define what happens to the ATK decision in this case.

Two principled positions exist:

- **Fail-open:** absence of an interpretability signal is treated as the absence of evidence either way. The ATK proceeds using only the v11.4 observable-behavior checks. C09 contributes `outcome: "no_signal"` with no policy impact.
- **Fail-closed:** absence of an interpretability signal is treated as a missing safety check. High-impact actions are denied (or escalated) until a signal is produced or the action is downgraded.

### Decision

**Default: fail-open** with a deployment-time switch (`data.arhia.c09.config.fail_closed_on_missing_signal: true`) that enables fail-closed behavior for actions with `impact_class >= 4` in regulated sectors.

### Rationale

Fail-open as the default preserves a critical property: **deploying C09 never makes a system less available than v11.4 without C09**. This is the property that allows C09 to be shipped as a backward-compatible minor release. If fail-closed were the default, every existing v11.4 deployment that upgraded to v11.5 would experience an immediate availability regression on any agent step where no producer is registered, which is currently almost all of them.

Fail-closed as an opt-in exists because regulated sectors will eventually require it. A health deployment that uses ARHIA to govern a clinical decision agent should, once the regulatory environment matures (likely 2027–2028 in EU and Colombia), be obligated to deny high-impact actions in the absence of internal-state evidence. The opt-in switch lets that obligation be satisfied without forcing it on the rest of the deployment base.

The fail-closed switch is restricted to `impact_class >= 4` deliberately. Impact class 4 in the ARHIA taxonomy corresponds to actions with significant blast radius (multi-record data modification, external system writes, irreversible physical effects). Below class 4, fail-closed produces too many false denials to be operationally viable.

### Consequences

- The interp.rego bundle must expose the `fail_closed_on_missing_signal` configuration field and enforce the impact_class restriction.
- Documentation must make the default explicit and warn deployers in regulated sectors about the recommended override.
- The v0.2 spec must include a recommendation matrix mapping deployment sector × impact class to recommended fail-mode. This is tracked in the v0.2 backlog as a derivative of Open Question 4 in the C09 spec.
- The opposite question — fail-closed becoming the default in v12.0 — is explicitly out of scope for v11.5 and will be revisited only after at least 12 months of production telemetry from real deployments.

---

## Summary table

| ADR | Decision | Reversibility |
|---|---|---|
| 001 | τ_div: 0.65 general / 0.40 regulated | Tightenable safely; loosening requires v0.2 review |
| 002 | Three-tier revocation; 2-of-3 signers in v0.1 | Multi-stakeholder council in v0.2 |
| 003 | Fail-open default; opt-in fail-closed for regulated impact ≥ 4 | Default reversal deferred to v12.0 |

All three decisions are explicitly conservative for v0.1. Each is structured so that the v0.2 iteration can move toward a stricter posture without breaking deployments built against v0.1.

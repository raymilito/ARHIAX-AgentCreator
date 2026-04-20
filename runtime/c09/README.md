# ARHIA v11.5 C09 — INTERP Bridge (Reference Implementation)

**Version:** `0.1.0-marketing-preview`
**Status:** Reference implementation for spec discussion. **Not intended for production deployment.**
**Maintainer:** Sinergia Consulting Group S.A.S. — Barranquilla, Colombia.

---

## What this is

This repository contains the reference implementation of the **ARHIA v11.5 C09 INTERP Bridge**, a subsystem that mediates between producers of mechanistic interpretability signals (e.g. Anthropic interpretability, Apollo Research, Goodfire, METR) and runtime AI governance, by way of a canonical signed evidence envelope (`INTERP-EV/1.0`).

The accompanying spec (`ARHIA_v11.5_C09_INTERP_Bridge_Spec_v0.1.docx`) describes the architectural positioning, the three evidence classes (A, B, C), the three new controls (INT-C01 / INT-C02 / INT-C03), and the integration with the ARHIA Action Trust Kernel (ATK).

## What this is NOT

- This is **not a production-ready governance runtime**.
- The Class C reference detector (v0.1 stepped, v1.1 continuous) is a **3-rule heuristic suitable for plumbing validation only**. It is explicitly scheduled for replacement by an accredited Class C producer in Phase 2.
- **Phase 2 (accredited producers in production) is open to research collaboration and is not part of Sinergia's 2026 commercial roadmap.**
- This repository is published as an **open spec contribution** to the AI governance ecosystem, not as a commercial offering.

## Repository status

| Component | Status |
|---|---|
| INTERP-EV/1.0 JSON Schema | ✓ validated (Draft 2020-12) |
| `interp.rego` policy bundle | ✓ Phase 0 |
| Three ADRs (`ADR-C09-001/002/003`) | ✓ Phase 0 |
| Reference implementation (5 modules) | ✓ Phase 1 |
| Test suite (Mythos + FPR + comparison) | ✓ Phase 1+ exit criteria PASS in development environment |
| Formal technical spec (byte-level INTERP-EV format, accreditation rules, revocation protocol) | ⚠ Open — referenced as "Open Questions 1–4" in the ADRs; targeted for v0.2 |
| Emergency revocation signatories (per ADR-C09-002) | ⚠ Not designated — required only if moving to production deployment, **out of scope for v0.1 marketing preview** |

## Installation

```bash
git clone <repo-url>
cd runtime/c09
pip install -e ".[dev]"
pytest -v

# Without install (development):
# PYTHONPATH=. pytest -v
# PYTHONPATH=. python arhia_c09/tests/test_mythos_no_macro.py
```

Expected output:

```
arhia_c09/tests/test_mythos_no_macro.py ........... 6 passed
arhia_c09/tests/test_fpr_compliant_traces.py ...... 100 traces, 0 force_hil
arhia_c09/tests/test_detector_comparison_v01_vs_v11.py ... PASS
```

## Layout

```
runtime/c09/
├── pyproject.toml
├── README.md                    (this file)
├── arhia_c09/
│   ├── __init__.py
│   ├── cir.py                   (INT-C01 — Calibrated Interpretability Registry)
│   ├── envelope.py              (INTERP-EV/1.0 + Ed25519)
│   ├── divergence.py            (Class C reference detector v0.1)
│   ├── divergence_v1_1.py       (Class C reference detector v1.1, continuous)
│   ├── gate.py                  (Divergence Gate, Python port of interp.rego)
│   ├── ledger.py                (INT-C03 — IEL HMAC chain)
│   └── tests/
│       ├── __init__.py
│       ├── test_mythos_no_macro.py
│       ├── test_fpr_compliant_traces.py
│       └── test_detector_comparison_v01_vs_v11.py
└── policy/
    └── interp.rego
```

## Citation

If you reference C09 or INTERP-EV/1.0 in academic work, please cite the forthcoming arXiv paper (preprint coming Q2 2026). Until then:

> Miller, R. (2026). *ARHIA v11.5 C09 INTERP Bridge: A canonical envelope for routing mechanistic interpretability signals into runtime AI governance.* Sinergia Consulting Group S.A.S., Reference Implementation v0.1.0-marketing-preview.

## License

Apache-2.0. See `LICENSE`.

## Contact

Ray Miller — Sinergia Consulting Group S.A.S. — Barranquilla, Colombia.
For research collaboration on Phase 2 (accredited producers): see contact details in the spec document.

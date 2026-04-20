"""
arhia_c09 — ARHIA v11.5 C09 INTERP Bridge reference implementation.

Reference implementation for spec discussion. NOT intended for production
deployment. Phase 2 (accredited producers in production) is open to research
collaboration and is not part of Sinergia's 2026 commercial roadmap.

Modules:
    cir        — Calibrated Interpretability Registry (INT-C01)
    envelope   — INTERP-EV/1.0 envelope + Ed25519 signing
    divergence — Class C reference detector (v0.1 stepped, v1.1 continuous)
    gate       — Divergence Gate (Python port of interp.rego)
    ledger     — Interpretability Evidence Ledger HMAC chain (INT-C03)
"""

__version__ = "0.1.0"
__status__ = "marketing-preview"

__all__ = [
    "cir",
    "envelope",
    "divergence",
    "gate",
    "ledger",
]

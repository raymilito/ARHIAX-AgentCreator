"""
ARHIA v11.5 — C09 Reference Implementation (Phase 1)
Module: cir.py — Calibrated Interpretability Registry (INT-C01)

In-memory registry for accredited interpretability producers. Production
deployments would back this with a signed Merkle log; v0.1 uses a dict.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional


@dataclass
class ProducerEntry:
    id: str
    public_key: bytes              # Ed25519 public key (32 bytes)
    domains: list[str]             # e.g. ["general", "health", "finance"]
    calibration_signed_at: datetime
    expires_at: datetime
    status: str = "active"         # active | suspended | revoked
    revocation_history: list[dict] = field(default_factory=list)

    def is_calibration_fresh(self, now: datetime, max_age_days: int = 90) -> bool:
        return (now - self.calibration_signed_at) <= timedelta(days=max_age_days)

    def is_active(self, now: datetime) -> bool:
        return self.status == "active" and self.expires_at > now


class CIR:
    """Calibrated Interpretability Registry (INT-C01)."""

    def __init__(self) -> None:
        self._producers: dict[str, ProducerEntry] = {}

    def register(self, entry: ProducerEntry) -> None:
        if entry.id in self._producers:
            raise ValueError(f"Producer {entry.id!r} already registered")
        self._producers[entry.id] = entry

    def get(self, producer_id: str) -> Optional[ProducerEntry]:
        return self._producers.get(producer_id)

    def is_accredited(self, producer_id: str, now: datetime) -> bool:
        entry = self._producers.get(producer_id)
        if entry is None:
            return False
        return entry.is_active(now) and entry.is_calibration_fresh(now)

    def suspend(self, producer_id: str, reason: str, now: datetime) -> None:
        entry = self._producers[producer_id]
        entry.status = "suspended"
        entry.revocation_history.append({
            "action": "suspend", "reason": reason, "at": now.isoformat()
        })

    def revoke(self, producer_id: str, reason: str, now: datetime) -> None:
        entry = self._producers[producer_id]
        entry.status = "revoked"
        entry.revocation_history.append({
            "action": "revoke", "reason": reason, "at": now.isoformat()
        })

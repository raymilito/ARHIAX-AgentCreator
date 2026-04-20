"""
ARHIA v11.5 — C09 Reference Implementation (Phase 1)
Module: ledger.py — Interpretability Evidence Ledger (INT-C03)

HMAC hash-chain ledger extending the EGA-C01/C02 chain-of-custody pattern
from ARHIA v11.4. Each entry binds: previous_hash + envelope + gate_decision.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
import hmac
import hashlib
import json


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


@dataclass
class LedgerEntry:
    seq: int
    timestamp: str
    envelope: dict | None
    gate_decision: dict
    prev_hash: str
    entry_hmac: str


class InterpretabilityLedger:
    """INT-C03 — append-only HMAC-chained ledger."""

    GENESIS = "0" * 64

    def __init__(self, secret: bytes) -> None:
        self._secret = secret
        self._entries: list[LedgerEntry] = []
        self._last_hash = self.GENESIS

    def append(
        self,
        envelope_dict: dict | None,
        gate_decision_dict: dict,
        now: datetime,
    ) -> LedgerEntry:
        seq = len(self._entries)
        body = {
            "seq": seq,
            "timestamp": now.isoformat(),
            "envelope": envelope_dict,
            "gate_decision": gate_decision_dict,
            "prev_hash": self._last_hash,
        }
        mac = hmac.new(self._secret, _canonical(body), hashlib.sha256).hexdigest()
        entry = LedgerEntry(
            seq=seq,
            timestamp=body["timestamp"],
            envelope=envelope_dict,
            gate_decision=gate_decision_dict,
            prev_hash=self._last_hash,
            entry_hmac=mac,
        )
        self._entries.append(entry)
        self._last_hash = mac
        return entry

    def verify_chain(self) -> bool:
        last = self.GENESIS
        for entry in self._entries:
            body = {
                "seq": entry.seq,
                "timestamp": entry.timestamp,
                "envelope": entry.envelope,
                "gate_decision": entry.gate_decision,
                "prev_hash": last,
            }
            expected = hmac.new(
                self._secret, _canonical(body), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected, entry.entry_hmac):
                return False
            if entry.prev_hash != last:
                return False
            last = entry.entry_hmac
        return True

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

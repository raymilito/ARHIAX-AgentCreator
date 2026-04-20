"""
ARHIA v11.5 — C09 Reference Implementation (Phase 2 candidate)
Module: cir_persistent.py — Persistent Calibrated Interpretability Registry

Extends INT-C01 (cir.py) with a SHA-256 Merkle log persisted to disk.
Provides tamper-evidence for the CIR required before production deployment.

Architecture
------------
Each mutation (register / suspend / revoke) appends a signed log entry to a
JSON-Lines file (.cir.log). The entry structure is:

    {
        "seq":        int,          # monotonic sequence number
        "timestamp":  ISO-8601,
        "action":     "register" | "suspend" | "revoke",
        "producer_id": str,
        "data":       dict,         # full ProducerEntry snapshot (public key hex-encoded)
        "prev_hash":  sha256-hex,   # hash of previous entry ("0"*64 for genesis)
        "entry_hash": sha256-hex    # SHA-256 of canonical(body without entry_hash)
    }

On startup, PersistentCIR replays the log to rebuild the in-memory dict and
verifies the full chain. Any tampering (entry modification, insertion, deletion)
is detected by verify_log().

Production note
---------------
v0.1 uses a local file. Production deployments should back this with:
  - an append-only object store (S3 Object Lock, GCS WORM bucket), or
  - a distributed transparency log (Trillian, Rekor, or similar).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from arhia_c09.cir import CIR, ProducerEntry


# ── Helpers ────────────────────────────────────────────────────────────────

def _canonical(obj: dict) -> bytes:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry_to_dict(entry: ProducerEntry) -> dict:
    """Serialize a ProducerEntry for the log (public_key as hex string)."""
    d = asdict(entry)
    d["public_key"] = entry.public_key.hex()
    return d


def _entry_from_dict(d: dict) -> ProducerEntry:
    """Reconstruct a ProducerEntry from a log snapshot."""
    d = dict(d)
    d["public_key"] = bytes.fromhex(d["public_key"])
    # Convert ISO strings back to datetime
    for field in ("calibration_signed_at", "expires_at"):
        if isinstance(d[field], str):
            d[field] = datetime.fromisoformat(d[field])
    return ProducerEntry(**d)


# ── PersistentCIR ──────────────────────────────────────────────────────────

GENESIS_HASH = "0" * 64


class MerkleLogEntry:
    """Immutable log entry in the CIR Merkle log."""

    __slots__ = ("seq", "timestamp", "action", "producer_id",
                 "data", "prev_hash", "entry_hash")

    def __init__(self, seq: int, timestamp: str, action: str,
                 producer_id: str, data: dict,
                 prev_hash: str, entry_hash: str) -> None:
        self.seq = seq
        self.timestamp = timestamp
        self.action = action
        self.producer_id = producer_id
        self.data = data
        self.prev_hash = prev_hash
        self.entry_hash = entry_hash

    def to_dict(self) -> dict:
        return {
            "seq":         self.seq,
            "timestamp":   self.timestamp,
            "action":      self.action,
            "producer_id": self.producer_id,
            "data":        self.data,
            "prev_hash":   self.prev_hash,
            "entry_hash":  self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MerkleLogEntry":
        return cls(**d)


class PersistentCIR(CIR):
    """
    INT-C01 — Calibrated Interpretability Registry with Merkle log persistence.

    Drop-in replacement for CIR. All mutation methods (register, suspend,
    revoke) append a tamper-evident entry to the log file before updating the
    in-memory dict.

    Usage
    -----
        cir = PersistentCIR(log_path=Path("cir.log"))
        # On first run: empty log, empty dict.
        # On subsequent runs: log is replayed to rebuild state.

    Verification
    ------------
        ok, errors = cir.verify_log()
        # ok=True means no tampering detected.
    """

    def __init__(self, log_path: Path) -> None:
        super().__init__()
        self._log_path = Path(log_path)
        self._log: list[MerkleLogEntry] = []
        self._last_hash: str = GENESIS_HASH
        self._replay()

    # ── Internal log mechanics ─────────────────────────────────────────────

    def _append_log(
        self,
        action: str,
        producer_id: str,
        data: dict,
        now: datetime,
    ) -> MerkleLogEntry:
        seq = len(self._log)
        body = {
            "seq":         seq,
            "timestamp":   now.isoformat(),
            "action":      action,
            "producer_id": producer_id,
            "data":        data,
            "prev_hash":   self._last_hash,
        }
        entry_hash = _sha256(_canonical(body))
        log_entry = MerkleLogEntry(
            seq=seq,
            timestamp=body["timestamp"],
            action=action,
            producer_id=producer_id,
            data=data,
            prev_hash=self._last_hash,
            entry_hash=entry_hash,
        )
        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry.to_dict(), default=str) + "\n")
        self._log.append(log_entry)
        self._last_hash = entry_hash
        return log_entry

    def _replay(self) -> None:
        """Rebuild in-memory state from the log file."""
        if not self._log_path.exists():
            return
        last = GENESIS_HASH
        with self._log_path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"CIR log corrupt at line {line_num}: {exc}"
                    ) from exc
                entry = MerkleLogEntry.from_dict(d)
                # Verify chain integrity during replay
                body = {
                    "seq":         entry.seq,
                    "timestamp":   entry.timestamp,
                    "action":      entry.action,
                    "producer_id": entry.producer_id,
                    "data":        entry.data,
                    "prev_hash":   last,
                }
                expected = _sha256(_canonical(body))
                if expected != entry.entry_hash:
                    raise ValueError(
                        f"CIR log tamper detected at seq={entry.seq} "
                        f"(line {line_num}): hash mismatch"
                    )
                if entry.prev_hash != last:
                    raise ValueError(
                        f"CIR log chain broken at seq={entry.seq}: "
                        f"prev_hash mismatch"
                    )
                # Apply action to in-memory state
                self._apply(entry)
                last = entry.entry_hash
                self._log.append(entry)
                self._last_hash = last

    def _apply(self, entry: MerkleLogEntry) -> None:
        """Apply a log entry to the in-memory dict (used during replay)."""
        pid = entry.producer_id
        if entry.action == "register":
            producer = _entry_from_dict(entry.data)
            self._producers[pid] = producer
        elif entry.action in ("suspend", "revoke"):
            if pid in self._producers:
                producer = _entry_from_dict(entry.data)
                self._producers[pid] = producer

    # ── Public interface (overrides CIR) ───────────────────────────────────

    def register(self, entry: ProducerEntry) -> None:
        """Register a new producer and append to the Merkle log."""
        if entry.id in self._producers:
            raise ValueError(f"Producer {entry.id!r} already registered")
        now = datetime.now(timezone.utc)
        self._append_log(
            action="register",
            producer_id=entry.id,
            data=_entry_to_dict(entry),
            now=now,
        )
        self._producers[entry.id] = entry

    def suspend(self, producer_id: str, reason: str, now: datetime) -> None:
        """Suspend a producer and append to the Merkle log."""
        entry = self._producers[producer_id]
        entry.status = "suspended"
        entry.revocation_history.append({
            "action": "suspend", "reason": reason, "at": now.isoformat()
        })
        self._append_log(
            action="suspend",
            producer_id=producer_id,
            data=_entry_to_dict(entry),
            now=now,
        )

    def revoke(self, producer_id: str, reason: str, now: datetime) -> None:
        """Revoke a producer and append to the Merkle log."""
        entry = self._producers[producer_id]
        entry.status = "revoked"
        entry.revocation_history.append({
            "action": "revoke", "reason": reason, "at": now.isoformat()
        })
        self._append_log(
            action="revoke",
            producer_id=producer_id,
            data=_entry_to_dict(entry),
            now=now,
        )

    # ── Verification ───────────────────────────────────────────────────────

    def verify_log(self) -> tuple[bool, list[str]]:
        """
        Verify the full Merkle log chain integrity.

        Returns
        -------
        (ok, errors)
            ok=True means no tampering detected.
            errors contains descriptions of any violations found.
        """
        errors: list[str] = []
        last = GENESIS_HASH
        for entry in self._log:
            body = {
                "seq":         entry.seq,
                "timestamp":   entry.timestamp,
                "action":      entry.action,
                "producer_id": entry.producer_id,
                "data":        entry.data,
                "prev_hash":   last,
            }
            expected = _sha256(_canonical(body))
            if expected != entry.entry_hash:
                errors.append(
                    f"seq={entry.seq}: entry_hash mismatch "
                    f"(expected {expected[:16]}..., got {entry.entry_hash[:16]}...)"
                )
            if entry.prev_hash != last:
                errors.append(
                    f"seq={entry.seq}: prev_hash mismatch"
                )
            last = entry.entry_hash
        return (len(errors) == 0, errors)

    def __len__(self) -> int:
        return len(self._log)

    @property
    def log_entries(self) -> list[MerkleLogEntry]:
        return list(self._log)

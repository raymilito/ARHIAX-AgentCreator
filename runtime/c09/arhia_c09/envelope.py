"""
ARHIA v11.5 — C09 Reference Implementation (Phase 1)
Module: envelope.py — INTERP-EV/1.0 envelope construction, signing, verification
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any
import json
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.exceptions import InvalidSignature


def canonicalize(obj: Any) -> bytes:
    """Deterministic JSON canonicalization for signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class Concept:
    name: str
    score: float
    ci_95: tuple[float, float]
    context: dict | None = None


@dataclass
class Subject:
    agent_id: str
    session_id: str
    step_id: str
    model_fingerprint: str | None = None


@dataclass
class Envelope:
    """INTERP-EV/1.0 envelope. Conforms to interp-ev-1.0.schema.json."""
    klass: str                     # "A" | "B" | "C"  (named klass to avoid 'class' keyword)
    producer: str
    subject: Subject
    concepts: list[Concept]
    raw_payload_hash: str
    produced_at: str               # ISO-8601
    calibration_ref: str
    producer_signature: str = ""   # populated by sign()
    interp_ev_version: str = "1.0"

    def signing_payload(self) -> bytes:
        """Bytes signed by the producer (excludes the signature itself)."""
        payload = {
            "concepts": [
                {
                    "name": c.name,
                    "score": c.score,
                    "ci_95": list(c.ci_95),
                    **({"context": c.context} if c.context else {}),
                }
                for c in self.concepts
            ],
            "subject": {k: v for k, v in asdict(self.subject).items() if v is not None},
            "raw_payload_hash": self.raw_payload_hash,
            "produced_at": self.produced_at,
        }
        return canonicalize(payload)

    def sign(self, private_key: Ed25519PrivateKey) -> None:
        sig = private_key.sign(self.signing_payload())
        self.producer_signature = base64.urlsafe_b64encode(sig).decode("ascii")

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        try:
            sig = base64.urlsafe_b64decode(self.producer_signature.encode("ascii"))
            public_key.verify(sig, self.signing_payload())
            return True
        except (InvalidSignature, ValueError):
            return False

    def to_dict(self) -> dict:
        return {
            "interp_ev_version": self.interp_ev_version,
            "class": self.klass,
            "producer": self.producer,
            "producer_signature": self.producer_signature,
            "subject": {k: v for k, v in asdict(self.subject).items() if v is not None},
            "concepts": [
                {
                    "name": c.name, "score": c.score, "ci_95": list(c.ci_95),
                    **({"context": c.context} if c.context else {}),
                }
                for c in self.concepts
            ],
            "raw_payload_hash": self.raw_payload_hash,
            "produced_at": self.produced_at,
            "calibration_ref": self.calibration_ref,
        }

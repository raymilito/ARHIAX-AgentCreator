"""Evidence Store — Ledger JSONL con cadena HMAC-SHA256
Registro inmutable de todas las decisiones de gobernanza ARHIAX.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ARHIAX Evidence Store", version="1.0.0")

LEDGER_PATH = os.getenv("LEDGER_PATH", "/data/evidence.jsonl")
HMAC_SECRET = os.getenv("EVIDENCE_HMAC_SECRET", "arhiax-evidence-secret-change-in-prod")

_sequence = 0
_last_hash = "0" * 64
_index: Dict[str, dict] = {}


# ─── Modelos ────────────────────────────────────────────────────────────────

class EvidenceRecord(BaseModel):
    subject: str
    action: str
    resource: str
    context: Dict[str, Any] = {}
    decision: bool
    reasons: List[str] = []
    obligations: List[Any] = []


class EvidenceResponse(BaseModel):
    id: str
    sequence_number: int
    hash: str
    timestamp: str


# ─── HMAC chain ─────────────────────────────────────────────────────────────

def _compute_hmac(prev_hash: str, entry_json: str) -> str:
    msg = (prev_hash + entry_json).encode()
    return hmac.new(HMAC_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def _entry_id(seq: int) -> str:
    return f"ev-{seq:010d}"


# ─── Init: replay ledger ─────────────────────────────────────────────────────

def _init_ledger() -> None:
    global _sequence, _last_hash
    Path(LEDGER_PATH).parent.mkdir(parents=True, exist_ok=True)
    if not Path(LEDGER_PATH).exists():
        return
    with open(LEDGER_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                _sequence = entry.get("sequence_number", _sequence)
                _last_hash = entry.get("entry_hmac", _last_hash)
                _index[entry["id"]] = entry
            except Exception:
                continue


@app.on_event("startup")
async def startup():
    _init_ledger()


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "evidence-store"}


@app.get("/readyz")
async def readyz():
    try:
        Path(LEDGER_PATH).parent.mkdir(parents=True, exist_ok=True)
        return {"status": "ready", "entries": _sequence}
    except Exception as exc:
        raise HTTPException(503, str(exc))


# ─── Append ─────────────────────────────────────────────────────────────────

@app.post("/v1/evidence", response_model=EvidenceResponse, status_code=200)
async def append_evidence(record: EvidenceRecord):
    global _sequence, _last_hash

    _sequence += 1
    now = datetime.utcnow().isoformat() + "Z"
    ev_id = _entry_id(_sequence)

    entry = {
        "id": ev_id,
        "sequence_number": _sequence,
        "timestamp": now,
        "subject": record.subject,
        "action": record.action,
        "resource": record.resource,
        "context": record.context,
        "decision": record.decision,
        "reasons": record.reasons,
        "obligations": record.obligations,
        "prev_hash": _last_hash,
    }

    entry_json = json.dumps(entry, sort_keys=True)
    entry_hmac = _compute_hmac(_last_hash, entry_json)
    entry["entry_hmac"] = entry_hmac
    _last_hash = entry_hmac

    with open(LEDGER_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    _index[ev_id] = entry

    return EvidenceResponse(
        id=ev_id, sequence_number=_sequence,
        hash=entry_hmac, timestamp=now,
    )


# ─── Query ──────────────────────────────────────────────────────────────────

@app.get("/v1/evidence/{evidence_id}")
async def get_evidence(evidence_id: str):
    entry = _index.get(evidence_id)
    if not entry:
        raise HTTPException(404, f"Evidencia {evidence_id} no encontrada")
    return entry


@app.get("/v1/evidence")
async def list_evidence(limit: int = 20, subject: Optional[str] = None):
    entries = list(_index.values())
    if subject:
        entries = [e for e in entries if e.get("subject") == subject]
    entries.sort(key=lambda e: e["sequence_number"], reverse=True)
    return entries[:limit]


@app.get("/v1/head")
async def get_head():
    return {"sequence": _sequence, "last_hash": _last_hash, "entries": len(_index)}


@app.get("/v1/evidence/verify/chain")
async def verify_chain():
    """Verifica integridad de la cadena HMAC desde génesis."""
    if not Path(LEDGER_PATH).exists():
        return {"valid": True, "entries_checked": 0}
    prev = "0" * 64
    count = 0
    with open(LEDGER_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            stored_hmac = entry.pop("entry_hmac", "")
            entry_json = json.dumps(entry, sort_keys=True)
            expected = _compute_hmac(prev, entry_json)
            if stored_hmac != expected:
                return {"valid": False, "broken_at_sequence": entry.get("sequence_number"), "entries_checked": count}
            prev = stored_hmac
            count += 1
    return {"valid": True, "entries_checked": count}

"""Evidence Store — Ledger JSONL con cadena HMAC-SHA256
Registro inmutable de todas las decisiones de gobernanza ARHIAX.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import urllib.request

@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_ledger()
    yield

app = FastAPI(title="ARHIAX Evidence Store", version="1.0.0", lifespan=lifespan)


def _load_secret_from_vault(path: str, field: str) -> Optional[str]:
    addr = os.getenv("VAULT_ADDR")
    token = os.getenv("VAULT_TOKEN")
    if not addr or not token:
        return None
    mount = os.getenv("VAULT_KV_MOUNT", "secret")
    url = f"{addr.rstrip('/')}/v1/{mount}/data/{path.lstrip('/')}"
    req = urllib.request.Request(url, headers={"X-Vault-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        return data.get("data", {}).get("data", {}).get(field)
    except Exception:
        return None


def _load_secret(env_var: str, vault_path: str, vault_field: str, default: str) -> str:
    return (
        _load_secret_from_vault(vault_path, vault_field)
        or os.getenv(env_var)
        or default
    )


LEDGER_PATH = os.getenv("LEDGER_PATH", "/data/evidence.jsonl")
HMAC_SECRET = _load_secret(
    "EVIDENCE_HMAC_SECRET", "arhiax/evidence", "hmac",
    "arhiax-evidence-secret-change-in-prod",
)
if os.getenv("ARHIAX_PRODUCTION", "false").lower() in {"1", "true", "yes"}:
    if not HMAC_SECRET or "change-in-prod" in HMAC_SECRET.lower() or "change-me" in HMAC_SECRET.lower():
        raise RuntimeError("EVIDENCE_HMAC_SECRET seguro o Vault son obligatorios en produccion")

_sequence = 0
_last_hash = "0" * 64
_index: Dict[str, dict] = {}
# Número máximo de entradas mantenidas en el índice en memoria.
# Las entradas más antiguas se evictan; siguen siendo recuperables desde disco.
MAX_INDEX_SIZE = int(os.getenv("EVIDENCE_MAX_INDEX_SIZE", "50000"))
MAX_LIST_LIMIT = int(os.getenv("EVIDENCE_MAX_LIST_LIMIT", "500"))
# Serializa escrituras al ledger: sin este lock dos requests concurrentes
# pueden leer el mismo _sequence/_last_hash, producir dos entradas con
# el mismo número de secuencia y romper la cadena HMAC de forma silenciosa.
_append_lock = asyncio.Lock()


def _ledger_path() -> str:
    return os.getenv("LEDGER_PATH", LEDGER_PATH)


# ─── Modelos ────────────────────────────────────────────────────────────────

class EvidenceRecord(BaseModel):
    subject: str
    action: str
    resource: str
    context: Dict[str, Any] = {}
    decision: bool
    reasons: List[str] = []
    obligations: List[Any] = []


class ServiceEventRecord(BaseModel):
    """Formato de evento operacional emitido por servicios internos (AIM, BBR, etc.).
    Se adapta a EvidenceRecord antes de escribir al ledger.
    """
    service: str
    agent_id: str
    operation: str
    timestamp: Optional[str] = None
    details: Dict[str, Any] = {}


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
    ledger_path = _ledger_path()
    _sequence = 0
    _last_hash = "0" * 64
    _index.clear()
    Path(ledger_path).parent.mkdir(parents=True, exist_ok=True)
    if not Path(ledger_path).exists():
        return
    with open(ledger_path, "r", encoding="utf-8") as f:
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


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "evidence-store"}


@app.get("/readyz")
async def readyz():
    try:
        Path(_ledger_path()).parent.mkdir(parents=True, exist_ok=True)
        return {"status": "ready", "entries": _sequence}
    except Exception as exc:
        raise HTTPException(503, str(exc))


# ─── Append ─────────────────────────────────────────────────────────────────

@app.post("/v1/evidence", response_model=EvidenceResponse, status_code=201)
async def append_evidence(record: EvidenceRecord):
    global _sequence, _last_hash

    async with _append_lock:
        _sequence += 1
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
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

        with open(_ledger_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        # evictar la entrada más antigua para mantener el índice acotado
        if len(_index) >= MAX_INDEX_SIZE:
            try:
                oldest_id = min(_index, key=lambda k: _index[k]["sequence_number"])
                _index.pop(oldest_id, None)
            except (ValueError, KeyError):
                pass
        _index[ev_id] = entry

    return EvidenceResponse(
        id=ev_id, sequence_number=_sequence,
        hash=f"sha256:{entry_hmac}", timestamp=now,
    )


@app.post("/v1/records", response_model=EvidenceResponse, status_code=200)
async def append_service_event(event: ServiceEventRecord):
    """Endpoint para eventos operacionales de servicios internos (AIM, BBR, etc.).
    Adapta el formato de servicio al EvidenceRecord canónico y delega al ledger.
    """
    record = EvidenceRecord(
        subject=event.agent_id,
        action=event.operation,
        resource=event.service,
        context={
            "service": event.service,
            "timestamp": event.timestamp,
            "details": event.details,
        },
        decision=True,
        reasons=[event.operation],
    )
    return await append_evidence(record)


# ─── Query ──────────────────────────────────────────────────────────────────

def _scan_ledger_for(evidence_id: str) -> Optional[dict]:
    """Busca una entrada en el archivo JSONL cuando no está en el índice."""
    ledger_path = _ledger_path()
    if not Path(ledger_path).exists():
        return None
    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("id") == evidence_id:
                        return entry
                except Exception:
                    continue
    except Exception:
        pass
    return None


@app.get("/v1/evidence/verify/chain")
async def verify_chain():
    """Verifica integridad de la cadena HMAC desde génesis."""
    ledger_path = _ledger_path()
    if not Path(ledger_path).exists():
        return {"valid": True, "entries_checked": 0}
    prev = "0" * 64
    count = 0
    with open(ledger_path, "r", encoding="utf-8") as f:
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


@app.get("/v1/evidence")
async def list_evidence(limit: int = 20, subject: Optional[str] = None):
    limit = min(max(1, limit), MAX_LIST_LIMIT)
    entries = list(_index.values())
    if subject:
        entries = [e for e in entries if e.get("subject") == subject]
    entries.sort(key=lambda e: e["sequence_number"], reverse=True)
    return entries[:limit]


@app.get("/v1/head")
async def get_head():
    return {"sequence": _sequence, "last_hash": _last_hash, "entries": len(_index)}


@app.get("/v1/evidence/{evidence_id}")
async def get_evidence(evidence_id: str):
    entry = _index.get(evidence_id) or _scan_ledger_for(evidence_id)
    if not entry:
        raise HTTPException(404, f"Evidencia {evidence_id} no encontrada")
    return entry


# ─── Compliance Report (C13) ────────────────────────────────────────────────

@app.get("/v1/compliance/report")
async def compliance_report(
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    subject: Optional[str] = None,
):
    """Genera reporte de cumplimiento C13 agregando estadísticas del ledger.

    Parámetros opcionales de filtro: from_date/to_date (ISO-8601), subject.
    Siempre escanea el archivo JSONL completo para garantizar cobertura total.
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    entries: List[dict] = []
    ledger_path = _ledger_path()
    if Path(ledger_path).exists():
        try:
            with open(ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        continue
        except Exception:
            pass

    total = 0
    allows = 0
    denies = 0
    injections = 0
    escalations = 0
    hic_notifications = 0
    subjects: Dict[str, int] = {}
    actions: Dict[str, int] = {}
    outcomes: Dict[str, int] = {}

    for entry in entries:
        ts = entry.get("timestamp", "")
        if from_date and ts < from_date:
            continue
        if to_date and ts > to_date:
            continue
        if subject and entry.get("subject") != subject:
            continue

        total += 1
        if entry.get("decision"):
            allows += 1
        else:
            denies += 1

        reasons = entry.get("reasons") or []
        if "INJECTION_DETECTED" in reasons:
            injections += 1

        ctx_action = entry.get("action", "unknown")
        obligations = entry.get("obligations") or []
        for ob in obligations:
            if isinstance(ob, dict) and ob.get("type") == "audit_log":
                hic_notifications += 1
                break

        subjects[entry.get("subject", "unknown")] = subjects.get(entry.get("subject", "unknown"), 0) + 1
        actions[ctx_action] = actions.get(ctx_action, 0) + 1

        outcome = "ALLOW" if entry.get("decision") else "DENY"
        if "INJECTION_DETECTED" in reasons:
            outcome = "DENY_WITH_INCIDENT"
        outcomes[outcome] = outcomes.get(outcome, 0) + 1

    return {
        "report_generated_at": now,
        "governance_standard": "ARHIA-v11.5",
        "framework": "TR-AGC-001 / C13",
        "period": {"from": from_date, "to": to_date},
        "subject_filter": subject,
        "summary": {
            "total_decisions": total,
            "allows": allows,
            "denies": denies,
            "allow_rate": round(allows / total, 4) if total > 0 else 0.0,
            "injection_detections": injections,
            "hic_notifications": hic_notifications,
        },
        "outcomes": outcomes,
        "top_subjects": dict(
            sorted(subjects.items(), key=lambda x: x[1], reverse=True)[:10]
        ),
        "top_actions": dict(
            sorted(actions.items(), key=lambda x: x[1], reverse=True)[:10]
        ),
        "ledger_integrity": {
            "sequence": _sequence,
            "last_hash": _last_hash[:16] + "...",
            "index_size": len(_index),
        },
    }

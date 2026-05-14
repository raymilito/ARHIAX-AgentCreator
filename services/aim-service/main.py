"""AIM Service — Agent Identity Management
Emite, valida y gestiona el ciclo de vida de credenciales de agentes ARHIAX.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import urllib.request
import urllib.error
import httpx


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="ARHIAX AIM Service", version="1.0.0", lifespan=lifespan)


def _load_secret_from_vault(path: str, field: str) -> Optional[str]:
    """Lee un secreto desde Vault KV v2 si VAULT_ADDR y VAULT_TOKEN existen.

    `path` es la ruta logica del KV (ej. "arhiax/aim"). `field` la clave dentro.
    Devuelve None si Vault no esta configurado o falla; el caller debe tener
    fallback a env var.
    """
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


HMAC_SECRET = _load_secret(
    "AIM_HMAC_SECRET", "arhiax/aim", "hmac", "arhiax-dev-secret-change-in-prod"
)
if os.getenv("ARHIAX_PRODUCTION", "false").lower() in {"1", "true", "yes"}:
    if not HMAC_SECRET or len(HMAC_SECRET) < 32:
        raise RuntimeError("AIM_HMAC_SECRET seguro o Vault son obligatorios en produccion")
    if "change-in-prod" in HMAC_SECRET.lower() or "change-me" in HMAC_SECRET.lower() or "dev" in HMAC_SECRET.lower():
        raise RuntimeError("AIM_HMAC_SECRET seguro o Vault son obligatorios en produccion")
DB_PATH = os.getenv("AIM_DB_PATH", "/data/aim.db")
EVIDENCE_STORE_URL = os.getenv("AIM_EVIDENCE_STORE_URL", "http://evidence-store:8090")
_CA_CERT = os.getenv("ARHIAX_CA_CERT") or False
_CLIENT_CERT = os.getenv("ARHIAX_TLS_CLIENT_CERT")
_CLIENT_KEY = os.getenv("ARHIAX_TLS_CLIENT_KEY")


def _mtls_kwargs() -> dict:
    kwargs = {"verify": _CA_CERT}
    if _CLIENT_CERT and _CLIENT_KEY:
        kwargs["cert"] = (_CLIENT_CERT, _CLIENT_KEY)
    return kwargs


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


# ─── Modelos ────────────────────────────────────────────────────────────────

class AgentRegistration(BaseModel):
    name: str
    description: str = ""
    department_id: str
    supervisor_id: str
    authorization_boundary_id: str = "default"
    initial_autonomy_level: str = "A0"
    permitted_tools: List[str] = []
    permitted_data_scopes: List[str] = []
    permitted_operations: List[str] = ["modelInvoke", "toolCall"]
    rotation_days: int = 90
    security_profile: dict = {}


class Credential(BaseModel):
    agent_id: str
    name: str
    supervisor_id: str
    department_id: str
    authorization_boundary_id: str
    autonomy_level: str
    credential_issued_at: str
    credential_expires_at: str
    rotation_policy: str
    lifecycle_state: str
    parent_chain_hmac: str
    permitted_tools: List[str]
    permitted_data_scopes: List[str]
    permitted_operations: List[str]
    security_profile: dict = {}


class AutonomyUpdate(BaseModel):
    autonomy_level: str
    reason: str = ""


# ─── DB ─────────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    db_path = os.getenv("AIM_DB_PATH", DB_PATH)
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id                TEXT PRIMARY KEY,
            name                    TEXT NOT NULL,
            description             TEXT DEFAULT '',
            department_id           TEXT NOT NULL,
            supervisor_id           TEXT NOT NULL,
            authorization_boundary_id TEXT NOT NULL,
            autonomy_level          TEXT NOT NULL DEFAULT 'A0',
            credential_issued_at    TEXT NOT NULL,
            credential_expires_at   TEXT NOT NULL,
            rotation_policy         TEXT NOT NULL,
            lifecycle_state         TEXT NOT NULL DEFAULT 'ACTIVE',
            parent_chain_hmac       TEXT NOT NULL,
            permitted_tools         TEXT NOT NULL DEFAULT '[]',
            permitted_data_scopes   TEXT NOT NULL DEFAULT '[]',
            permitted_operations    TEXT NOT NULL DEFAULT '[]',
            security_profile        TEXT NOT NULL DEFAULT '{}',
            created_at              TEXT NOT NULL
        )
    """)
    columns = [row[1] for row in conn.execute("PRAGMA table_info(agents)").fetchall()]
    if "security_profile" not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN security_profile TEXT NOT NULL DEFAULT '{}'")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS autonomy_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT NOT NULL,
            old_level   TEXT NOT NULL,
            new_level   TEXT NOT NULL,
            reason      TEXT DEFAULT '',
            changed_at  TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _chain_hmac(agent_id: str, supervisor_id: str, issued_at: str) -> str:
    msg = f"{agent_id}:{supervisor_id}:{issued_at}".encode()
    return hmac.new(HMAC_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def _verify_parent_chain_hmac(agent_id: str, supervisor_id: str, issued_at: str, stored_hmac: str) -> bool:
    expected = _chain_hmac(agent_id, supervisor_id, issued_at)
    return hmac.compare_digest(expected, stored_hmac)


def _parse_rotation_deadline(credential_expires_at: str) -> Optional[datetime]:
    try:
        if credential_expires_at.endswith('Z'):
            return datetime.fromisoformat(credential_expires_at.replace('Z', '+00:00'))
        return datetime.fromisoformat(credential_expires_at)
    except (ValueError, AttributeError):
        return None


def _check_rotation_needed(credential_expires_at: str) -> bool:
    expires = _parse_rotation_deadline(credential_expires_at)
    if not expires:
        return False
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_until_expiry = (expires - now).days
    return days_until_expiry <= 7


async def _log_to_evidence_store(agent_id: str, operation: str, details: dict) -> None:
    try:
        payload = {
            "service": "aim-service",
            "agent_id": agent_id,
            "operation": operation,
            "timestamp": _utc_iso(_utc_now()),
            "details": details,
        }
        async with httpx.AsyncClient(timeout=2.0, **_mtls_kwargs()) as client:
            await client.post(
                f"{EVIDENCE_STORE_URL.rstrip('/')}/v1/records",
                json=payload,
            )
    except Exception:
        pass


def _row_to_credential(row: sqlite3.Row) -> Credential:
    return Credential(
        agent_id=row["agent_id"],
        name=row["name"],
        supervisor_id=row["supervisor_id"],
        department_id=row["department_id"],
        authorization_boundary_id=row["authorization_boundary_id"],
        autonomy_level=row["autonomy_level"],
        credential_issued_at=row["credential_issued_at"],
        credential_expires_at=row["credential_expires_at"],
        rotation_policy=row["rotation_policy"],
        lifecycle_state=row["lifecycle_state"],
        parent_chain_hmac=row["parent_chain_hmac"],
        permitted_tools=json.loads(row["permitted_tools"]),
        permitted_data_scopes=json.loads(row["permitted_data_scopes"]),
        permitted_operations=json.loads(row["permitted_operations"]),
        security_profile=json.loads(row["security_profile"] or "{}"),
    )


# ─── Lifecycle ──────────────────────────────────────────────────────────────

# ─── Health ─────────────────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "aim", "version": "1.0.0"}


@app.get("/readyz")
async def readyz():
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        return {"status": "ready"}
    except Exception as exc:
        raise HTTPException(503, str(exc))


# ─── Registro ───────────────────────────────────────────────────────────────

@app.post("/v1/agents/register", response_model=Credential, status_code=201)
async def register_agent(reg: AgentRegistration):
    agent_id = f"agent-{uuid.uuid4().hex[:12]}"
    now = _utc_now()
    expires = now + timedelta(days=reg.rotation_days)
    issued_at = _utc_iso(now)
    expires_at = _utc_iso(expires)
    chain_hmac = _chain_hmac(agent_id, reg.supervisor_id, issued_at)

    conn = get_db()
    conn.execute(
        """INSERT INTO agents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            agent_id, reg.name, reg.description,
            reg.department_id, reg.supervisor_id, reg.authorization_boundary_id,
            "A0", issued_at, expires_at, f"{reg.rotation_days}d",
            "ACTIVE", chain_hmac,
            json.dumps(reg.permitted_tools),
            json.dumps(reg.permitted_data_scopes),
            json.dumps(reg.permitted_operations),
            json.dumps(reg.security_profile or {}),
            issued_at,
        ),
    )
    conn.commit()
    conn.close()

    await _log_to_evidence_store(agent_id, "CREDENTIAL_REGISTERED", {
        "name": reg.name,
        "supervisor_id": reg.supervisor_id,
        "autonomy_level": "A0",
        "rotation_days": reg.rotation_days,
    })

    return Credential(
        agent_id=agent_id, name=reg.name,
        supervisor_id=reg.supervisor_id, department_id=reg.department_id,
        authorization_boundary_id=reg.authorization_boundary_id,
        autonomy_level="A0", credential_issued_at=issued_at,
        credential_expires_at=expires_at, rotation_policy=f"{reg.rotation_days}d",
        lifecycle_state="ACTIVE", parent_chain_hmac=chain_hmac,
        permitted_tools=reg.permitted_tools,
        permitted_data_scopes=reg.permitted_data_scopes,
        permitted_operations=reg.permitted_operations,
        security_profile=reg.security_profile or {},
    )


# ─── Consulta ───────────────────────────────────────────────────────────────

@app.get("/v1/credentials/{agent_id}", response_model=Credential)
async def get_credential(agent_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, f"Agente {agent_id} no encontrado")
    if not _verify_parent_chain_hmac(row["agent_id"], row["supervisor_id"], row["credential_issued_at"], row["parent_chain_hmac"]):
        raise HTTPException(500, "Parent chain HMAC verification failed")
    return _row_to_credential(row)


@app.get("/v1/agents")
async def list_agents():
    conn = get_db()
    rows = conn.execute(
        "SELECT agent_id, name, autonomy_level, lifecycle_state, created_at FROM agents ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Ciclo de vida ──────────────────────────────────────────────────────────

@app.post("/v1/credentials/{agent_id}/rotate")
async def rotate_credential(agent_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    now = _utc_now()
    issued = _utc_iso(now)
    rotation_policy = row["rotation_policy"] or "90d"
    try:
        rotation_days = int(rotation_policy.rstrip("d"))
    except (ValueError, AttributeError):
        rotation_days = 90
    expires = _utc_iso(now + timedelta(days=rotation_days))
    new_hmac = _chain_hmac(agent_id, row["supervisor_id"], issued)
    conn.execute(
        "UPDATE agents SET credential_issued_at=?, credential_expires_at=?, parent_chain_hmac=?, lifecycle_state='ACTIVE' WHERE agent_id=?",
        (issued, expires, new_hmac, agent_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    conn.close()

    await _log_to_evidence_store(agent_id, "CREDENTIAL_ROTATED", {
        "issued_at": issued,
        "expires_at": expires,
    })

    return _row_to_credential(row)


@app.post("/v1/credentials/{agent_id}/revoke")
async def revoke_credential(agent_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    conn.execute("UPDATE agents SET lifecycle_state='SUSPENDED' WHERE agent_id=?", (agent_id,))
    conn.commit()
    row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    conn.close()

    await _log_to_evidence_store(agent_id, "CREDENTIAL_REVOKED", {})

    return _row_to_credential(row)


@app.post("/v1/credentials/{agent_id}/autonomy")
async def update_autonomy(agent_id: str, update: AutonomyUpdate):
    valid_levels = {"A0", "A1", "A2", "A3", "A4"}
    if update.autonomy_level not in valid_levels:
        raise HTTPException(400, f"Nivel inválido: {update.autonomy_level}. Válidos: {valid_levels}")
    conn = get_db()
    row = conn.execute("SELECT autonomy_level FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    old_level = row["autonomy_level"]
    now = _utc_iso(_utc_now())
    conn.execute("UPDATE agents SET autonomy_level=? WHERE agent_id=?", (update.autonomy_level, agent_id))
    conn.execute(
        "INSERT INTO autonomy_history (agent_id, old_level, new_level, reason, changed_at) VALUES (?,?,?,?,?)",
        (agent_id, old_level, update.autonomy_level, update.reason, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    conn.close()

    await _log_to_evidence_store(agent_id, "AUTONOMY_UPDATED", {
        "old_level": old_level,
        "new_level": update.autonomy_level,
        "reason": update.reason,
    })

    return _row_to_credential(row)


@app.get("/v1/credentials/{agent_id}/history")
async def autonomy_history(agent_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM autonomy_history WHERE agent_id=? ORDER BY changed_at DESC", (agent_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

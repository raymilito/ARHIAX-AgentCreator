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
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ARHIAX AIM Service", version="1.0.0")

HMAC_SECRET = os.getenv("AIM_HMAC_SECRET", "arhiax-dev-secret-change-in-prod")
DB_PATH = os.getenv("AIM_DB_PATH", "/data/aim.db")


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


class AutonomyUpdate(BaseModel):
    autonomy_level: str
    reason: str = ""


# ─── DB ─────────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
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
            created_at              TEXT NOT NULL
        )
    """)
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
    )


# ─── Lifecycle ──────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    init_db()


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
    now = datetime.utcnow()
    expires = now + timedelta(days=reg.rotation_days)
    issued_at = now.isoformat() + "Z"
    expires_at = expires.isoformat() + "Z"
    chain_hmac = _chain_hmac(agent_id, reg.supervisor_id, issued_at)

    conn = get_db()
    conn.execute(
        """INSERT INTO agents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            agent_id, reg.name, reg.description,
            reg.department_id, reg.supervisor_id, reg.authorization_boundary_id,
            "A0", issued_at, expires_at, f"{reg.rotation_days}d",
            "ACTIVE", chain_hmac,
            json.dumps(reg.permitted_tools),
            json.dumps(reg.permitted_data_scopes),
            json.dumps(reg.permitted_operations),
            issued_at,
        ),
    )
    conn.commit()
    conn.close()

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
    )


# ─── Consulta ───────────────────────────────────────────────────────────────

@app.get("/v1/credentials/{agent_id}", response_model=Credential)
async def get_credential(agent_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, f"Agente {agent_id} no encontrado")
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
    now = datetime.utcnow()
    issued = now.isoformat() + "Z"
    expires = (now + timedelta(days=90)).isoformat() + "Z"
    new_hmac = _chain_hmac(agent_id, row["supervisor_id"], issued)
    conn.execute(
        "UPDATE agents SET credential_issued_at=?, credential_expires_at=?, parent_chain_hmac=?, lifecycle_state='ACTIVE' WHERE agent_id=?",
        (issued, expires, new_hmac, agent_id),
    )
    conn.commit()
    conn.close()
    return {"rotated": True, "agent_id": agent_id, "new_issued_at": issued}


@app.post("/v1/credentials/{agent_id}/revoke")
async def revoke_credential(agent_id: str):
    conn = get_db()
    conn.execute("UPDATE agents SET lifecycle_state='SUSPENDED' WHERE agent_id=?", (agent_id,))
    conn.commit()
    conn.close()
    return {"revoked": True, "agent_id": agent_id}


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
    now = datetime.utcnow().isoformat() + "Z"
    conn.execute("UPDATE agents SET autonomy_level=? WHERE agent_id=?", (update.autonomy_level, agent_id))
    conn.execute(
        "INSERT INTO autonomy_history (agent_id, old_level, new_level, reason, changed_at) VALUES (?,?,?,?,?)",
        (agent_id, old_level, update.autonomy_level, update.reason, now),
    )
    conn.commit()
    conn.close()
    return {"agent_id": agent_id, "old_level": old_level, "new_level": update.autonomy_level}


@app.get("/v1/credentials/{agent_id}/history")
async def autonomy_history(agent_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM autonomy_history WHERE agent_id=? ORDER BY changed_at DESC", (agent_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

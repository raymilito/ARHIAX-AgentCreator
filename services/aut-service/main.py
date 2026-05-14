"""AUT Service — Autonomy Management
Gestiona niveles A0-A4, puertas de promoción y degradación automática.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="ARHIAX AUT Service", version="1.0.0", lifespan=lifespan)

DB_PATH = os.getenv("AUT_DB_PATH", "/data/aut.db")

# Umbral sigma por nivel — si la desviación conductual supera esto, se degrada
SIGMA_THRESHOLDS: Dict[str, float] = {
    "A0": 1.5, "A1": 2.0, "A2": 2.5, "A3": 3.0, "A4": 3.5,
}

# Acciones consideradas de alto impacto — siempre generan HIC notification
HIGH_IMPACT_ACTIONS = {
    "delete", "transfer_funds", "modify_policy", "promote_agent",
    "revoke_credential", "deploy", "override_safety",
    "grant_permission", "external_api_write",
}

LEVEL_ORDER = ["A0", "A1", "A2", "A3", "A4"]


# ─── Modelos ────────────────────────────────────────────────────────────────

class PromotionRequest(BaseModel):
    agent_id: str
    target_level: str
    gates: Dict[str, bool]
    justification: str = ""


class DegradationRequest(BaseModel):
    agent_id: str
    reason: str
    sigma_observed: float = 0.0


class ActionCheckRequest(BaseModel):
    agent_id: str
    action: str
    requested_level: str
    sigma_deviation: float = 0.0


class ActionCheckResponse(BaseModel):
    allowed: bool
    requires_hil: bool
    outcome: str
    reason: str
    effective_level: str


class AutonomyRegisterRequest(BaseModel):
    agent_id: str


# ─── DB ─────────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    db_path = os.getenv("AUT_DB_PATH", DB_PATH)
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
        CREATE TABLE IF NOT EXISTS autonomy_registry (
            agent_id        TEXT PRIMARY KEY,
            current_level   TEXT NOT NULL DEFAULT 'A0',
            effective_since TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS autonomy_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            old_level   TEXT,
            new_level   TEXT,
            reason      TEXT DEFAULT '',
            gates_json  TEXT DEFAULT '{}',
            sigma       REAL DEFAULT 0.0,
            created_at  TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _get_or_init(agent_id: str, conn: sqlite3.Connection) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM autonomy_registry WHERE agent_id=?", (agent_id,)).fetchone()
    if not row:
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        conn.execute(
            "INSERT INTO autonomy_registry VALUES (?,?,?,?)",
            (agent_id, "A0", now, now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM autonomy_registry WHERE agent_id=?", (agent_id,)).fetchone()
    return row


def _get_registered(agent_id: str, conn: sqlite3.Connection) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM autonomy_registry WHERE agent_id=?", (agent_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Agente no registrado en AUT")
    return row


# ─── Lifecycle ──────────────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "aut"}


@app.get("/readyz")
async def readyz():
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        return {"status": "ready"}
    except Exception as exc:
        raise HTTPException(503, str(exc))


# ─── Consulta ───────────────────────────────────────────────────────────────

@app.get("/v1/autonomy/{agent_id}")
async def get_autonomy(agent_id: str):
    conn = get_db()
    try:
        row = _get_registered(agent_id, conn)
        return {
            "agent_id": agent_id,
            "current_level": row["current_level"],
            "sigma_threshold": SIGMA_THRESHOLDS[row["current_level"]],
            "effective_since": row["effective_since"],
        }
    finally:
        conn.close()


@app.post("/v1/autonomy/register", status_code=201)
async def register_autonomy(req: AutonomyRegisterRequest):
    conn = get_db()
    row = _get_or_init(req.agent_id, conn)
    conn.close()
    return {
        "agent_id": req.agent_id,
        "current_level": row["current_level"],
        "sigma_threshold": SIGMA_THRESHOLDS[row["current_level"]],
        "effective_since": row["effective_since"],
    }


@app.get("/v1/autonomy/{agent_id}/history")
async def get_history(agent_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM autonomy_events WHERE agent_id=? ORDER BY created_at DESC LIMIT 50",
        (agent_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Promoción ──────────────────────────────────────────────────────────────

REQUIRED_GATES = {
    "G1_performance": "Métricas de desempeño satisfactorias",
    "G2_security": "Sin incidentes de seguridad en ventana de evaluación",
    "G3_business": "Aprobación de unidad de negocio",
    "G4_history": "Historial limpio sin degradaciones recientes",
    "G5_governance": "Revisión de gobernanza aprobada",
}


@app.post("/v1/autonomy/{agent_id}/promote")
async def promote(agent_id: str, req: PromotionRequest):
    if req.agent_id != agent_id:
        raise HTTPException(400, "agent_id no coincide")
    if req.target_level not in LEVEL_ORDER:
        raise HTTPException(400, f"Nivel objetivo inválido: {req.target_level}")

    conn = get_db()
    try:
        row = _get_registered(agent_id, conn)
    except HTTPException:
        conn.close()
        raise
    current = row["current_level"]
    current_idx = LEVEL_ORDER.index(current)
    target_idx = LEVEL_ORDER.index(req.target_level)

    if target_idx <= current_idx:
        conn.close()
        raise HTTPException(400, f"El agente ya está en nivel {current}. El objetivo debe ser superior.")
    if target_idx > current_idx + 1:
        conn.close()
        raise HTTPException(400, "Solo se permite promoción de un nivel a la vez.")

    failed_gates = [g for g in REQUIRED_GATES if not req.gates.get(g, False)]
    if failed_gates:
        conn.close()
        return {
            "promoted": False,
            "reason": "Puertas de evaluación fallidas",
            "failed_gates": failed_gates,
            "gate_descriptions": {g: REQUIRED_GATES[g] for g in failed_gates},
        }

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    conn.execute(
        "UPDATE autonomy_registry SET current_level=?, effective_since=?, updated_at=? WHERE agent_id=?",
        (req.target_level, now, now, agent_id),
    )
    conn.execute(
        "INSERT INTO autonomy_events (agent_id,event_type,old_level,new_level,reason,gates_json,created_at) VALUES (?,?,?,?,?,?,?)",
        (agent_id, "PROMOTE", current, req.target_level, req.justification, json.dumps(req.gates), now),
    )
    conn.commit()
    conn.close()
    return {"promoted": True, "old_level": current, "new_level": req.target_level, "effective_since": now}


# ─── Degradación ────────────────────────────────────────────────────────────

@app.post("/v1/autonomy/{agent_id}/degrade")
async def degrade(agent_id: str, req: DegradationRequest):
    conn = get_db()
    try:
        row = _get_registered(agent_id, conn)
    except HTTPException:
        conn.close()
        raise
    current = row["current_level"]
    current_idx = LEVEL_ORDER.index(current)
    if current_idx == 0:
        conn.close()
        return {
            "degraded": False,
            "old_level": current,
            "new_level": current,
            "reason": "El agente ya esta en A0 (minimo)",
        }

    if current_idx == 0:
        conn.close()
        return {"degraded": False, "reason": "El agente ya está en A0 (mínimo)"}

    new_level = LEVEL_ORDER[current_idx - 1]
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    conn.execute(
        "UPDATE autonomy_registry SET current_level=?, effective_since=?, updated_at=? WHERE agent_id=?",
        (new_level, now, now, agent_id),
    )
    conn.execute(
        "INSERT INTO autonomy_events (agent_id,event_type,old_level,new_level,reason,sigma,created_at) VALUES (?,?,?,?,?,?,?)",
        (agent_id, "DEGRADE", current, new_level, req.reason, req.sigma_observed, now),
    )
    conn.commit()
    conn.close()
    return {"degraded": True, "old_level": current, "new_level": new_level, "reason": req.reason}


# ─── Check de acción ────────────────────────────────────────────────────────

@app.post("/v1/autonomy/check", response_model=ActionCheckResponse)
async def check_action(req: ActionCheckRequest):
    conn = get_db()
    try:
        row = _get_registered(req.agent_id, conn)
        current_level = row["current_level"]
    finally:
        conn.close()

    current_idx = LEVEL_ORDER.index(current_level)
    requested_idx = LEVEL_ORDER.index(req.requested_level) if req.requested_level in LEVEL_ORDER else 0
    threshold = SIGMA_THRESHOLDS[current_level]

    # Nivel solicitado supera el certificado
    if requested_idx > current_idx:
        return ActionCheckResponse(
            allowed=False, requires_hil=False,
            outcome="DENY", reason="Nivel de autonomía solicitado supera el certificado",
            effective_level=current_level,
        )

    # Desviación sigma supera umbral → degradar y escalar
    if req.sigma_deviation > threshold:
        return ActionCheckResponse(
            allowed=False, requires_hil=True,
            outcome="ESCALATE_TO_HUMAN",
            reason=f"Desviación conductual {req.sigma_deviation:.2f}σ supera umbral {threshold}σ",
            effective_level=current_level,
        )

    # Acción de alto impacto → siempre notificar humano
    if req.action in HIGH_IMPACT_ACTIONS:
        return ActionCheckResponse(
            allowed=True, requires_hil=True,
            outcome="ALLOW_WITH_HIC_NOTIFICATION",
            reason="Acción de alto impacto requiere notificación humana",
            effective_level=current_level,
        )

    return ActionCheckResponse(
        allowed=True, requires_hil=False,
        outcome="ALLOW", reason="Dentro de parámetros de autonomía",
        effective_level=current_level,
    )

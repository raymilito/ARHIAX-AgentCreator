"""BBR Service — Behavioral Baseline Registry
Registra observaciones conductuales de agentes y calcula desviación sigma.
"""
from __future__ import annotations

import math
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="ARHIAX BBR Service", version="1.0.0", lifespan=lifespan)

DB_PATH = os.getenv("BBR_DB_PATH", "/data/bbr.db")
MAX_LIST_LIMIT = int(os.getenv("BBR_MAX_LIST_LIMIT", "1000"))


# ─── Modelos ────────────────────────────────────────────────────────────────

class Observation(BaseModel):
    agent_id: str
    operation_type: str
    tool_name: Optional[str] = None
    duration_ms: float = 0.0
    token_count: int = 0
    outcome: str = "ALLOW"
    tags: List[str] = []


class BaselineScore(BaseModel):
    agent_id: str
    sigma_deviation: float
    sample_count: int
    mean_duration_ms: float
    std_duration_ms: float
    mean_tokens: float
    std_tokens: float
    has_baseline: bool


# ─── DB ─────────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    db_path = os.getenv("BBR_DB_PATH", DB_PATH)
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
        CREATE TABLE IF NOT EXISTS observations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id        TEXT NOT NULL,
            operation_type  TEXT NOT NULL,
            tool_name       TEXT,
            duration_ms     REAL NOT NULL DEFAULT 0,
            token_count     INTEGER NOT NULL DEFAULT 0,
            outcome         TEXT NOT NULL DEFAULT 'ALLOW',
            tags            TEXT DEFAULT '[]',
            observed_at     TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_agent ON observations(agent_id)")
    conn.commit()
    conn.close()


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "bbr"}


@app.get("/readyz")
async def readyz():
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        return {"status": "ready"}
    except Exception as exc:
        raise HTTPException(503, str(exc))


# ─── Registro de observación ────────────────────────────────────────────────

@app.post("/v1/baseline/{agent_id}/observe")
async def record_observation(agent_id: str, obs: Observation):
    import json
    if obs.agent_id != agent_id:
        raise HTTPException(400, "agent_id no coincide")
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    conn.execute(
        "INSERT INTO observations (agent_id,operation_type,tool_name,duration_ms,token_count,outcome,tags,observed_at) VALUES (?,?,?,?,?,?,?,?)",
        (agent_id, obs.operation_type, obs.tool_name, obs.duration_ms, obs.token_count, obs.outcome, json.dumps(obs.tags), now),
    )
    conn.commit()
    conn.close()
    return {"status": "recorded", "recorded": True, "agent_id": agent_id}


# ─── Estadísticas de baseline ───────────────────────────────────────────────

@app.get("/v1/baseline/{agent_id}", response_model=BaselineScore)
async def get_baseline(agent_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT duration_ms, token_count FROM observations WHERE agent_id=? ORDER BY observed_at DESC LIMIT 200",
        (agent_id,),
    ).fetchall()
    conn.close()

    if len(rows) < 5:
        return BaselineScore(
            agent_id=agent_id, sigma_deviation=0.0,
            sample_count=len(rows), mean_duration_ms=0.0,
            std_duration_ms=0.0, mean_tokens=0.0, std_tokens=0.0,
            has_baseline=False,
        )

    durations = [r["duration_ms"] for r in rows]
    tokens = [r["token_count"] for r in rows]

    mean_d = sum(durations) / len(durations)
    std_d = math.sqrt(sum((x - mean_d) ** 2 for x in durations) / len(durations)) or 1.0
    mean_t = sum(tokens) / len(tokens)
    std_t = math.sqrt(sum((x - mean_t) ** 2 for x in tokens) / len(tokens)) or 1.0

    return BaselineScore(
        agent_id=agent_id, sigma_deviation=0.0,
        sample_count=len(rows), mean_duration_ms=mean_d,
        std_duration_ms=std_d, mean_tokens=mean_t, std_tokens=std_t,
        has_baseline=True,
    )


# ─── Cálculo de desviación sigma ────────────────────────────────────────────

class DeviationRequest(BaseModel):
    duration_ms: float
    token_count: int


@app.post("/v1/baseline/{agent_id}/score", response_model=BaselineScore)
async def compute_score(agent_id: str, req: DeviationRequest):
    baseline = await get_baseline(agent_id)

    if not baseline.has_baseline:
        return baseline

    sigma_d = abs(req.duration_ms - baseline.mean_duration_ms) / (baseline.std_duration_ms or 1.0)
    sigma_t = abs(req.token_count - baseline.mean_tokens) / (baseline.std_tokens or 1.0)
    sigma = max(sigma_d, sigma_t)

    baseline.sigma_deviation = sigma
    return baseline


# ─── Historial de observaciones ─────────────────────────────────────────────

@app.get("/v1/baseline/{agent_id}/observations")
async def list_observations(agent_id: str, limit: int = 50):
    limit = min(max(1, limit), MAX_LIST_LIMIT)
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM observations WHERE agent_id=? ORDER BY observed_at DESC LIMIT ?",
        (agent_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

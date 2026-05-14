"""HIC Service — Human-in-the-Loop Checkpoints
Gestiona tickets de aprobación humana con SLA y notificaciones webhook.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if WEBHOOK_URL:
        _validate_webhook_url(WEBHOOK_URL)
    yield

app = FastAPI(title="ARHIAX HIC Service", version="1.0.0", lifespan=lifespan)

DB_PATH = os.getenv("HIC_DB_PATH", "/data/hic.db")
MAX_LIST_LIMIT = int(os.getenv("HIC_MAX_LIST_LIMIT", "500"))
WEBHOOK_URL = os.getenv("HIC_WEBHOOK_URL", "")
# Hosts permitidos para el webhook. Si se define, solo se aceptan esos hosts.
# Separados por coma. Si vacío, se permite cualquier host http/https.
_WEBHOOK_ALLOWED_HOSTS: set = set(
    h.strip() for h in os.getenv("HIC_WEBHOOK_ALLOWED_HOSTS", "").split(",") if h.strip()
)

SLA_MINUTES = {"CRITICAL": 5, "HIGH": 15, "MEDIUM": 60, "LOW": 1440}


def _validate_webhook_url(url: str) -> None:
    """Valida que la URL del webhook tenga esquema http/https y host permitido.

    Previene SSRF: sin validación, WEBHOOK_URL podría apuntar a servicios
    internos (aim-service, gateway, etc.) y exfiltrar datos o disparar acciones.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"HIC_WEBHOOK_URL debe usar esquema http o https, recibido: {parsed.scheme!r}"
        )
    host = parsed.hostname or ""
    if not host:
        raise ValueError("HIC_WEBHOOK_URL no tiene host válido")
    if _WEBHOOK_ALLOWED_HOSTS and host not in _WEBHOOK_ALLOWED_HOSTS:
        raise ValueError(
            f"HIC_WEBHOOK_URL host {host!r} no está en HIC_WEBHOOK_ALLOWED_HOSTS"
        )


# ─── Modelos ────────────────────────────────────────────────────────────────

class TicketCreate(BaseModel):
    agent_id: str
    action: str
    resource: str
    reason: str
    severity: str = "MEDIUM"
    context: dict = {}
    decision_id: str = ""


class TicketDecision(BaseModel):
    approved: bool
    reviewer_id: str
    notes: str = ""


class Ticket(BaseModel):
    ticket_id: str
    agent_id: str
    action: str
    resource: str
    reason: str
    severity: str
    status: str
    context: dict
    decision_id: str
    sla_deadline: str
    created_at: str
    resolved_at: Optional[str]
    reviewer_id: Optional[str]
    notes: Optional[str]


# ─── DB ─────────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    db_path = os.getenv("HIC_DB_PATH", DB_PATH)
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
        CREATE TABLE IF NOT EXISTS tickets (
            ticket_id   TEXT PRIMARY KEY,
            agent_id    TEXT NOT NULL,
            action      TEXT NOT NULL,
            resource    TEXT NOT NULL,
            reason      TEXT NOT NULL,
            severity    TEXT NOT NULL DEFAULT 'MEDIUM',
            status      TEXT NOT NULL DEFAULT 'PENDING',
            context     TEXT NOT NULL DEFAULT '{}',
            decision_id TEXT DEFAULT '',
            sla_deadline TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            resolved_at TEXT,
            reviewer_id TEXT,
            notes       TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_agent ON tickets(agent_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status)")
    conn.commit()
    conn.close()


def _row_to_ticket(row: sqlite3.Row) -> Ticket:
    return Ticket(
        ticket_id=row["ticket_id"],
        agent_id=row["agent_id"],
        action=row["action"],
        resource=row["resource"],
        reason=row["reason"],
        severity=row["severity"],
        status=row["status"],
        context=json.loads(row["context"]),
        decision_id=row["decision_id"] or "",
        sla_deadline=row["sla_deadline"],
        created_at=row["created_at"],
        resolved_at=row["resolved_at"],
        reviewer_id=row["reviewer_id"],
        notes=row["notes"],
    )


async def _notify_webhook(ticket: Ticket) -> None:
    if not WEBHOOK_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(WEBHOOK_URL, json={
                "event": "hic.ticket.created",
                "ticket_id": ticket.ticket_id,
                "agent_id": ticket.agent_id,
                "action": ticket.action,
                "resource": ticket.resource,
                "severity": ticket.severity,
                "reason": ticket.reason,
                "sla_deadline": ticket.sla_deadline,
                "approve_url": f"/v1/tickets/{ticket.ticket_id}/approve",
                "reject_url": f"/v1/tickets/{ticket.ticket_id}/reject",
            })
    except Exception:
        pass


# ─── Lifecycle ──────────────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "hic"}


@app.get("/readyz")
async def readyz():
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        return {"status": "ready"}
    except Exception as exc:
        raise HTTPException(503, str(exc))


# ─── Crear ticket ───────────────────────────────────────────────────────────

@app.post("/v1/tickets", response_model=Ticket, status_code=201)
async def create_ticket(req: TicketCreate):
    sev = req.severity.upper()
    if sev not in SLA_MINUTES:
        sev = "MEDIUM"
    ticket_id = f"hic-{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc)
    deadline = now + timedelta(minutes=SLA_MINUTES[sev])

    conn = get_db()
    conn.execute(
        """INSERT INTO tickets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ticket_id, req.agent_id, req.action, req.resource, req.reason,
            sev, "PENDING", json.dumps(req.context), req.decision_id,
            deadline.isoformat().replace("+00:00", "Z"), now.isoformat().replace("+00:00", "Z"),
            None, None, None,
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM tickets WHERE ticket_id=?", (ticket_id,)).fetchone()
    conn.close()

    ticket = _row_to_ticket(row)
    await _notify_webhook(ticket)
    return ticket


# ─── Consultar ──────────────────────────────────────────────────────────────

@app.get("/v1/tickets/{ticket_id}", response_model=Ticket)
async def get_ticket(ticket_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM tickets WHERE ticket_id=?", (ticket_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, f"Ticket {ticket_id} no encontrado")
    return _row_to_ticket(row)


@app.get("/v1/tickets")
async def list_tickets(agent_id: Optional[str] = None, status: Optional[str] = None, limit: int = 50):
    limit = min(max(1, limit), MAX_LIST_LIMIT)
    conn = get_db()
    query = "SELECT * FROM tickets WHERE 1=1"
    params = []
    if agent_id:
        query += " AND agent_id=?"
        params.append(agent_id)
    if status:
        query += " AND status=?"
        params.append(status.upper())
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [_row_to_ticket(r) for r in rows]


# ─── Resolución ─────────────────────────────────────────────────────────────

@app.post("/v1/tickets/{ticket_id}/approve")
async def approve_ticket(ticket_id: str, decision: TicketDecision):
    conn = get_db()
    row = conn.execute("SELECT * FROM tickets WHERE ticket_id=?", (ticket_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    if row["status"] != "PENDING":
        conn.close()
        raise HTTPException(409, f"Ticket ya está en estado {row['status']}")
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    conn.execute(
        "UPDATE tickets SET status='APPROVED', resolved_at=?, reviewer_id=?, notes=? WHERE ticket_id=?",
        (now, decision.reviewer_id, decision.notes, ticket_id),
    )
    conn.commit()
    conn.close()
    return {
        "ticket_id": ticket_id,
        "status": "APPROVED",
        "resolved_at": now,
        "reviewer_id": decision.reviewer_id,
    }


@app.post("/v1/tickets/{ticket_id}/reject")
async def reject_ticket(ticket_id: str, decision: TicketDecision):
    conn = get_db()
    row = conn.execute("SELECT * FROM tickets WHERE ticket_id=?", (ticket_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    if row["status"] != "PENDING":
        conn.close()
        raise HTTPException(409, f"Ticket ya está en estado {row['status']}")
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    conn.execute(
        "UPDATE tickets SET status='REJECTED', resolved_at=?, reviewer_id=?, notes=? WHERE ticket_id=?",
        (now, decision.reviewer_id, decision.notes, ticket_id),
    )
    conn.commit()
    conn.close()
    return {"ticket_id": ticket_id, "status": "REJECTED", "resolved_at": now}


# ─── SLA monitoring ─────────────────────────────────────────────────────────

@app.get("/v1/tickets/expired/check")
async def check_expired():
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    rows = conn.execute(
        "SELECT ticket_id, agent_id, severity FROM tickets WHERE status='PENDING' AND sla_deadline < ?",
        (now,),
    ).fetchall()
    expired = [dict(r) for r in rows]
    if expired:
        ids = [r["ticket_id"] for r in expired]
        conn.execute(
            f"UPDATE tickets SET status='SLA_EXPIRED' WHERE ticket_id IN ({','.join('?' * len(ids))})",
            ids,
        )
        conn.commit()
    conn.close()
    return {"expired_count": len(expired), "expired_tickets": expired}

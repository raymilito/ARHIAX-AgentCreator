"""HIC Service — Human-in-the-Loop Checkpoints
Gestiona tickets de aprobación humana con SLA y notificaciones webhook.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ARHIAX HIC Service", version="1.0.0")

DB_PATH = os.getenv("HIC_DB_PATH", "/data/hic.db")
WEBHOOK_URL = os.getenv("HIC_WEBHOOK_URL", "")

SLA_MINUTES = {"CRITICAL": 5, "HIGH": 15, "MEDIUM": 60, "LOW": 1440}


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
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
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

@app.on_event("startup")
async def startup():
    init_db()


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
    now = datetime.utcnow()
    deadline = now + timedelta(minutes=SLA_MINUTES[sev])

    conn = get_db()
    conn.execute(
        """INSERT INTO tickets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ticket_id, req.agent_id, req.action, req.resource, req.reason,
            sev, "PENDING", json.dumps(req.context), req.decision_id,
            deadline.isoformat() + "Z", now.isoformat() + "Z",
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
        raise HTTPException(400, f"Ticket ya está en estado {row['status']}")
    now = datetime.utcnow().isoformat() + "Z"
    conn.execute(
        "UPDATE tickets SET status='APPROVED', resolved_at=?, reviewer_id=?, notes=? WHERE ticket_id=?",
        (now, decision.reviewer_id, decision.notes, ticket_id),
    )
    conn.commit()
    conn.close()
    return {"ticket_id": ticket_id, "status": "APPROVED", "resolved_at": now}


@app.post("/v1/tickets/{ticket_id}/reject")
async def reject_ticket(ticket_id: str, decision: TicketDecision):
    conn = get_db()
    row = conn.execute("SELECT * FROM tickets WHERE ticket_id=?", (ticket_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    if row["status"] != "PENDING":
        conn.close()
        raise HTTPException(400, f"Ticket ya está en estado {row['status']}")
    now = datetime.utcnow().isoformat() + "Z"
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
    now = datetime.utcnow().isoformat() + "Z"
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

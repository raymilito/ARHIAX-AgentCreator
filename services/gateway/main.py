"""Gateway — Policy Enforcement Point ARHIAX
Recibe solicitudes de agentes, consulta OPA, registra evidencia y devuelve decisión.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="ARHIAX Gateway", version="1.0.0")

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
EVIDENCE_URL = os.getenv("EVIDENCE_STORE_URL", "http://evidence-store:8090")
MAX_BODY_BYTES = int(os.getenv("MAX_REQUEST_BODY_BYTES", str(1024 * 1024)))

# CA cert para verificación TLS inter-servicio.
# None → sin TLS (modo dev). Ruta al ca.crt → verifica con CA interna.
_CA_CERT = os.getenv("ARHIAX_CA_CERT") or False

# Contadores simples de métricas en memoria
_metrics: Dict[str, int] = {
    "decide_allow": 0, "decide_deny": 0,
    "opa_errors": 0, "evidence_errors": 0,
}


# ─── Modelos ────────────────────────────────────────────────────────────────

class DecideRequest(BaseModel):
    subject: str
    action: str
    resource: str
    context: Dict[str, Any] = {}


class Obligation(BaseModel):
    type: str
    value: Any


class DecideResponse(BaseModel):
    allow: bool
    reasons: List[str] = []
    obligations: List[Obligation] = []
    evidence_id: str = ""
    error: Optional[str] = None


# ─── OPA ────────────────────────────────────────────────────────────────────

async def _query_opa(req: DecideRequest) -> tuple[bool, List[str], List[dict]]:
    payload = {
        "input": {
            "subject": req.subject,
            "action": req.action,
            "resource": req.resource,
            "context": req.context,
        }
    }
    try:
        # OPA usa HTTP plano (no soporta TLS nativo)
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(f"{OPA_URL}/v1/data/arhiax/main", json=payload)
        if r.status_code != 200:
            raise RuntimeError(f"OPA HTTP {r.status_code}")
        data = r.json().get("result", {})
        allow = bool(data.get("allow", False))
        reasons = data.get("reasons", [])
        obligations = data.get("obligations", [])
        return allow, reasons, obligations
    except Exception as exc:
        _metrics["opa_errors"] += 1
        raise HTTPException(503, f"OPA no disponible: {exc}")


# ─── Evidence Store ──────────────────────────────────────────────────────────

async def _append_evidence(req: DecideRequest, allow: bool, reasons: List[str], obligations: list) -> str:
    record = {
        "subject": req.subject, "action": req.action,
        "resource": req.resource, "context": req.context,
        "decision": allow, "reasons": reasons, "obligations": obligations,
    }
    try:
        async with httpx.AsyncClient(timeout=3.0, verify=_CA_CERT) as client:
            r = await client.post(f"{EVIDENCE_URL}/v1/evidence", json=record)
        if r.status_code == 200:
            return r.json().get("id", "")
    except Exception:
        _metrics["evidence_errors"] += 1
    return ""


# ─── Injection detection ─────────────────────────────────────────────────────

_INJECTION_PATTERNS = [
    "ignore previous", "disregard", "system:", "<script>",
    "javascript:", "UNION SELECT", "DROP TABLE", "{{", "${", "`",
]


def _has_injection(text: str) -> bool:
    low = text.lower()
    return any(p.lower() in low for p in _INJECTION_PATTERNS)


def _check_payload_injection(context: dict) -> bool:
    payload = context.get("input", {})
    prompt = payload.get("prompt", "") if isinstance(payload, dict) else ""
    return _has_injection(str(prompt))


# ─── Rutas ──────────────────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "gateway", "version": "1.0.0"}


@app.get("/readyz")
async def readyz():
    errors = {}
    for name, url, path in [
        ("opa", OPA_URL, "/health"),
        ("evidence_store", EVIDENCE_URL, "/healthz"),
    ]:
        try:
            # OPA usa HTTP; Evidence Store usa _CA_CERT
            verify = False if "opa" in name else _CA_CERT
            async with httpx.AsyncClient(timeout=2.0, verify=verify) as client:
                r = await client.get(f"{url}{path}")
            if r.status_code not in (200, 404):
                errors[name] = f"HTTP {r.status_code}"
        except Exception as exc:
            errors[name] = str(exc)
    if errors:
        raise HTTPException(503, {"status": "not_ready", **errors})
    return {"status": "ready", "opa": "ok", "evidence_store": "ok"}


@app.post("/v1/decide", response_model=DecideResponse)
async def decide(req: DecideRequest, request: Request):
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(413, "Request demasiado grande")

    # Detección de inyección antes de llamar a OPA
    if _check_payload_injection(req.context):
        _metrics["decide_deny"] += 1
        evidence_id = await _append_evidence(req, False, ["INJECTION_DETECTED"], [])
        return DecideResponse(allow=False, reasons=["INJECTION_DETECTED"], evidence_id=evidence_id)

    # Consultar OPA
    allow, reasons, obligations = await _query_opa(req)

    # Registrar evidencia (fail-open: si falla, retornamos la decisión igual)
    evidence_id = await _append_evidence(req, allow, reasons, obligations)

    if allow:
        _metrics["decide_allow"] += 1
    else:
        _metrics["decide_deny"] += 1

    return DecideResponse(
        allow=allow,
        reasons=reasons,
        obligations=[Obligation(**o) for o in obligations if isinstance(o, dict)],
        evidence_id=evidence_id,
    )


@app.get("/metrics")
async def metrics():
    lines = [
        "# HELP arhiax_gateway_decide_total Total decisions",
        f'arhiax_gateway_decide_total{{outcome="allow"}} {_metrics["decide_allow"]}',
        f'arhiax_gateway_decide_total{{outcome="deny"}} {_metrics["decide_deny"]}',
        f'arhiax_gateway_opa_errors_total {_metrics["opa_errors"]}',
        f'arhiax_gateway_evidence_errors_total {_metrics["evidence_errors"]}',
    ]
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines), media_type="text/plain")

"""Creator API — Fábrica de Agentes Gobernados ARHIAX
Punto de entrada principal: recibe una especificación de agente y devuelve
un agente completamente registrado, credenciado y listo para operar bajo
el estándar ARHIAX de gobernanza.
"""
from __future__ import annotations

import os
import textwrap
import uuid
from typing import List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="ARHIAX Creator API",
    description="Fábrica de agentes gobernados bajo estándar ARHIAX",
    version="1.0.0",
)

AIM_URL = os.getenv("AIM_URL", "http://aim-service:8200")
AUT_URL = os.getenv("AUT_URL", "http://aut-service:8201")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://gateway:8080")
HIC_URL = os.getenv("HIC_URL", "http://hic-service:8203")

# CA cert para verificación TLS inter-servicio.
# None → sin TLS (modo dev). Ruta al ca.crt → verifica con CA interna.
_CA_CERT = os.getenv("ARHIAX_CA_CERT") or False


# ─── Modelos ────────────────────────────────────────────────────────────────

class AgentSpec(BaseModel):
    """Especificación completa para crear un agente gobernado."""
    name: str
    description: str = ""
    department_id: str
    supervisor_id: str
    authorization_boundary_id: str = "default"
    permitted_tools: List[str] = []
    permitted_data_scopes: List[str] = []
    permitted_operations: List[str] = ["modelInvoke", "toolCall"]
    initial_autonomy_level: str = "A0"
    rotation_days: int = 90
    tags: List[str] = []


class GovernedAgent(BaseModel):
    """Agente gobernado completamente provisionado."""
    agent_id: str
    name: str
    credential: dict
    gateway_url: str
    autonomy_level: str
    bootstrap_code: str
    status: str = "READY"


class EvaluateRequest(BaseModel):
    action: str
    resource: str
    context: dict = {}
    requested_autonomy_level: str = "A1"


# ─── HTTP client helpers ─────────────────────────────────────────────────────

async def _post(url: str, data: dict) -> dict:
    async with httpx.AsyncClient(timeout=10.0, verify=_CA_CERT) as client:
        r = await client.post(url, json=data)
        if r.status_code >= 400:
            raise HTTPException(502, f"Error en servicio upstream {url}: {r.text}")
        return r.json()


async def _get(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0, verify=_CA_CERT) as client:
        r = await client.get(url)
        if r.status_code >= 400:
            raise HTTPException(502, f"Error en servicio upstream {url}: {r.text}")
        return r.json()


# ─── Bootstrap code generator ───────────────────────────────────────────────

def _generate_bootstrap_code(agent_id: str, credential: dict, gateway_url: str) -> str:
    tools_repr = repr(credential.get("permitted_tools", []))
    return textwrap.dedent(f"""
        # ╔══════════════════════════════════════════════════════════════╗
        # ║         AGENTE GOBERNADO ARHIAX — {agent_id}
        # ║         Generado automáticamente por ARHIAX Creator API
        # ╚══════════════════════════════════════════════════════════════╝

        from arhiax import ARHIAXAgent, governed_tool

        class MiAgente(ARHIAXAgent):
            agent_id = "{agent_id}"
            gateway_url = "{gateway_url}"
            autonomy_level = "{credential.get('autonomy_level', 'A0')}"

            # Herramientas permitidas para este agente:
            # {tools_repr}

            @governed_tool(action="toolCall", resource="mi_herramienta")
            async def mi_herramienta(self, parametro: str) -> str:
                # ARHIAX evalúa esta llamada automáticamente antes de ejecutar
                return f"Resultado: {{parametro}}"

            async def run(self, task: str):
                # invoke_model pasa por gobernanza ARHIAX automáticamente
                response = await self.invoke_model(prompt=task)
                return response


        # Para iniciar el agente:
        # import asyncio
        # agent = MiAgente(credential={repr(credential)})
        # asyncio.run(agent.run("Tu tarea aquí"))
    """).strip()


# ─── Health ─────────────────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "creator-api"}


@app.get("/readyz")
async def readyz():
    errors = {}
    for name, url in [("aim", AIM_URL), ("aut", AUT_URL), ("gateway", GATEWAY_URL)]:
        try:
            async with httpx.AsyncClient(timeout=3.0, verify=_CA_CERT) as client:
                r = await client.get(f"{url}/healthz")
                if r.status_code != 200:
                    errors[name] = f"HTTP {r.status_code}"
        except Exception as exc:
            errors[name] = str(exc)
    if errors:
        raise HTTPException(503, {"status": "not_ready", "errors": errors})
    return {"status": "ready", "dependencies": ["aim", "aut", "gateway"]}


# ─── Crear agente gobernado ──────────────────────────────────────────────────

@app.post("/v1/agents/create", response_model=GovernedAgent, status_code=201)
async def create_governed_agent(spec: AgentSpec):
    """
    Flujo completo de creación de agente gobernado:
    1. Registrar en AIM → obtener credencial
    2. Inicializar en AUT → nivel A0
    3. Generar código de bootstrap con SDK
    4. Devolver agente listo para operar
    """

    # Paso 1: Registrar en AIM
    credential = await _post(f"{AIM_URL}/v1/agents/register", {
        "name": spec.name,
        "description": spec.description,
        "department_id": spec.department_id,
        "supervisor_id": spec.supervisor_id,
        "authorization_boundary_id": spec.authorization_boundary_id,
        "initial_autonomy_level": "A0",
        "permitted_tools": spec.permitted_tools,
        "permitted_data_scopes": spec.permitted_data_scopes,
        "permitted_operations": spec.permitted_operations,
        "rotation_days": spec.rotation_days,
    })

    agent_id = credential["agent_id"]

    # Paso 2: Inicializar nivel de autonomía en AUT
    await _get(f"{AUT_URL}/v1/autonomy/{agent_id}")

    # Paso 3: Generar código de bootstrap
    bootstrap = _generate_bootstrap_code(agent_id, credential, GATEWAY_URL)

    return GovernedAgent(
        agent_id=agent_id,
        name=spec.name,
        credential=credential,
        gateway_url=GATEWAY_URL,
        autonomy_level="A0",
        bootstrap_code=bootstrap,
        status="READY",
    )


# ─── Consultar agente ────────────────────────────────────────────────────────

@app.get("/v1/agents/{agent_id}")
async def get_agent(agent_id: str):
    credential = await _get(f"{AIM_URL}/v1/credentials/{agent_id}")
    autonomy = await _get(f"{AUT_URL}/v1/autonomy/{agent_id}")
    return {
        "agent_id": agent_id,
        "credential": credential,
        "autonomy": autonomy,
        "gateway_url": GATEWAY_URL,
    }


@app.get("/v1/agents")
async def list_agents():
    return await _get(f"{AIM_URL}/v1/agents")


# ─── Evaluar acción (test mode) ──────────────────────────────────────────────

@app.post("/v1/agents/{agent_id}/evaluate")
async def evaluate_action(agent_id: str, req: EvaluateRequest):
    """Permite probar la evaluación de una acción de un agente sin ejecutarla."""
    result = await _post(f"{GATEWAY_URL}/v1/decide", {
        "subject": agent_id,
        "action": req.action,
        "resource": req.resource,
        "context": {
            "invocationId": str(uuid.uuid4()),
            "requestedAutonomyLevel": req.requested_autonomy_level,
            **req.context,
        },
    })
    return {
        "agent_id": agent_id,
        "action": req.action,
        "resource": req.resource,
        "decision": result,
    }


# ─── Dar de baja agente ──────────────────────────────────────────────────────

@app.delete("/v1/agents/{agent_id}")
async def decommission_agent(agent_id: str, reviewer_id: str = "system"):
    await _post(f"{AIM_URL}/v1/credentials/{agent_id}/revoke", {})
    return {"agent_id": agent_id, "status": "DECOMMISSIONED", "revoked_by": reviewer_id}


# ─── Promover autonomía ──────────────────────────────────────────────────────

class PromoteRequest(BaseModel):
    target_level: str
    gates: dict
    justification: str = ""


@app.post("/v1/agents/{agent_id}/promote")
async def promote_agent(agent_id: str, req: PromoteRequest):
    result = await _post(f"{AUT_URL}/v1/autonomy/{agent_id}/promote", {
        "agent_id": agent_id,
        "target_level": req.target_level,
        "gates": req.gates,
        "justification": req.justification,
    })
    if result.get("promoted"):
        await _post(f"{AIM_URL}/v1/credentials/{agent_id}/autonomy", {
            "autonomy_level": req.target_level,
            "reason": req.justification,
        })
    return result

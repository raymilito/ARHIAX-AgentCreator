"""Creator API for governed ARHIAX agents."""
from __future__ import annotations

import hashlib
import json
import os
import textwrap
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="ARHIAX Creator API",
    description="Factory for governed ARHIAX agents",
    version="1.0.0",
)

AIM_URL = os.getenv("AIM_URL", "http://aim-service:8200")
AUT_URL = os.getenv("AUT_URL", "http://aut-service:8201")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://gateway:8080")
HIC_URL = os.getenv("HIC_URL", "http://hic-service:8203")
CREDENTIAL_BROKER_URL = os.getenv("CREDENTIAL_BROKER_URL", "http://credential-broker:8204")

_CA_CERT = os.getenv("ARHIAX_CA_CERT") or False
_CLIENT_CERT = os.getenv("ARHIAX_TLS_CLIENT_CERT")
_CLIENT_KEY = os.getenv("ARHIAX_TLS_CLIENT_KEY")


def _mtls_kwargs() -> dict:
    kwargs: dict = {"verify": _CA_CERT}
    if _CLIENT_CERT and _CLIENT_KEY:
        kwargs["cert"] = (_CLIENT_CERT, _CLIENT_KEY)
    return kwargs


class AgentSpec(BaseModel):
    """Complete specification for a governed agent."""

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
    security_profile: Optional[dict] = None


class GovernedAgent(BaseModel):
    """Provisioned governed agent."""

    agent_id: str
    name: str
    credential: dict
    gateway_url: str
    autonomy_level: str
    bootstrap_code: str
    bootstrap_config: dict
    security_profile: dict
    status: str = "READY"


class EvaluateRequest(BaseModel):
    action: str
    resource: str
    context: dict = {}
    requested_autonomy_level: str = "A1"


async def _post(url: str, data: dict) -> dict:
    async with httpx.AsyncClient(timeout=10.0, **_mtls_kwargs()) as client:
        r = await client.post(url, json=data)
        if r.status_code >= 400:
            raise HTTPException(502, f"Error en servicio upstream {url}: {r.text}")
        return r.json()


async def _get(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0, **_mtls_kwargs()) as client:
        r = await client.get(url)
        if r.status_code >= 400:
            raise HTTPException(502, f"Error en servicio upstream {url}: {r.text}")
        return r.json()


def _default_security_profile(spec: AgentSpec) -> dict:
    return {
        "token_mode": "brokered_ephemeral",
        "zero_token_in_context": True,
        "require_pop": True,
        "tool_token_ttl_seconds": 60,
        "high_risk_token_ttl_seconds": 30,
        "revocation_mode": "redis+jti",
        "step_up_required_for": [],
        "allowed_audiences": spec.permitted_tools or ["*"],
        "context_binding_mode": "resource",
        "sanitize_tool_outputs": True,
        "enforce_broker_for_tools": True,
    }


def _merge_security_profile(spec: AgentSpec) -> dict:
    profile = _default_security_profile(spec)
    if spec.security_profile:
        profile.update(spec.security_profile)
    return profile


def _bootstrap_config(agent_id: str, credential: dict, gateway_url: str, security_profile: dict) -> dict:
    return {
        "agent_id": agent_id,
        "gateway_url": gateway_url,
        "credential_broker_url": CREDENTIAL_BROKER_URL,
        "autonomy_level": credential.get("autonomy_level", "A0"),
        "permitted_tools": credential.get("permitted_tools", []),
        "credential": credential,
        "security_profile": security_profile,
    }


def _py_literal(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def _generate_bootstrap_code(config: dict) -> str:
    tools_repr = _py_literal(config["permitted_tools"])
    agent_id = _py_literal(config["agent_id"])
    gateway_url = _py_literal(config["gateway_url"])
    autonomy_level = _py_literal(config["autonomy_level"])
    credential_broker_url = _py_literal(config["credential_broker_url"])
    return textwrap.dedent(f"""
        # ARHIAX governed agent bootstrap.
        # Credential and security_profile are in bootstrap_config (returned alongside
        # this code). Load them from a secrets manager — never hardcode them here.

        from arhiax import ARHIAXAgent, governed_tool

        class MiAgente(ARHIAXAgent):
            agent_id = {agent_id}
            gateway_url = {gateway_url}
            autonomy_level = {autonomy_level}
            credential_broker_url = {credential_broker_url}

            # Permitted tools for this agent:
            # {tools_repr}

            @governed_tool(action="toolCall", resource="mi_herramienta")
            async def mi_herramienta(self, parametro: str, _arhiax_runtime_auth=None) -> str:
                # Runtime auth is injected by the SDK and must never be exposed
                # to prompts, logs, traces, or model-visible output.
                return f"Resultado: {{parametro}}"

            async def run(self, task: str):
                response = await self.invoke_model(prompt=task)
                return response


        # Startup example (load credential from your secrets manager):
        # import asyncio
        # credential = secrets_manager.get("arhiax/{agent_id}/credential")
        # security_profile = secrets_manager.get("arhiax/{agent_id}/security_profile")
        # agent = MiAgente(credential=credential, security_profile=security_profile)
        # asyncio.run(agent.run("Tu tarea aqui"))
    """).strip()


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "creator-api"}


@app.get("/readyz")
async def readyz():
    errors = {}
    for name, url in [("aim", AIM_URL), ("aut", AUT_URL), ("gateway", GATEWAY_URL)]:
        try:
            async with httpx.AsyncClient(timeout=3.0, **_mtls_kwargs()) as client:
                r = await client.get(f"{url}/healthz")
                if r.status_code != 200:
                    errors[name] = f"HTTP {r.status_code}"
        except Exception as exc:
            errors[name] = str(exc)
    if errors:
        raise HTTPException(503, {"status": "not_ready", "errors": errors})
    return {"status": "ready", "dependencies": ["aim", "aut", "gateway"]}


@app.post("/v1/agents/create", response_model=GovernedAgent, status_code=201)
async def create_governed_agent(spec: AgentSpec):
    """Create a fully registered, credentialed, governed agent."""

    security_profile = _merge_security_profile(spec)
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
        "security_profile": security_profile,
    })

    agent_id = credential["agent_id"]
    security_profile = credential.get("security_profile") or security_profile
    credential["security_profile"] = security_profile

    await _post(f"{AUT_URL}/v1/autonomy/register", {"agent_id": agent_id})

    bootstrap_cfg = _bootstrap_config(agent_id, credential, GATEWAY_URL, security_profile)
    bootstrap = _generate_bootstrap_code(bootstrap_cfg)

    return GovernedAgent(
        agent_id=agent_id,
        name=spec.name,
        credential=credential,
        gateway_url=GATEWAY_URL,
        autonomy_level="A0",
        bootstrap_code=bootstrap,
        bootstrap_config=bootstrap_cfg,
        security_profile=security_profile,
        status="READY",
    )


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


@app.post("/v1/agents/{agent_id}/evaluate")
async def evaluate_action(agent_id: str, req: EvaluateRequest):
    """Evaluate an action for an agent without executing it."""
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


@app.delete("/v1/agents/{agent_id}")
async def decommission_agent(agent_id: str, reviewer_id: str = "system"):
    await _post(f"{AIM_URL}/v1/credentials/{agent_id}/revoke", {})
    return {"agent_id": agent_id, "status": "DECOMMISSIONED", "revoked_by": reviewer_id}


class AibomComponent(BaseModel):
    component_id: str
    type: str
    name: str
    version: str = "1.0"
    state: str = "ACTIVE"
    provenance: Dict[str, str] = {}


class AibomRecord(BaseModel):
    aibom_id: str
    agent_id: str
    name: str
    version: str = "1.0"
    generated_at: str
    governance_standard: str = "ARHIA-v11.5"
    autonomy_level: str
    supervisor_id: str
    department_id: str
    authorization_boundary_id: str
    credential_expires_at: str
    permitted_tools: List[str]
    permitted_operations: List[str]
    permitted_data_scopes: List[str]
    security_profile: dict
    components: List[AibomComponent]
    controls_active: List[str]


def _build_aibom(credential: dict) -> AibomRecord:
    agent_id = credential["agent_id"]
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    aibom_id = f"aibom-{hashlib.sha256(f'{agent_id}:{now}'.encode()).hexdigest()[:16]}"

    components = [
        AibomComponent(
            component_id=f"tool-{hashlib.sha256(t.encode()).hexdigest()[:12]}",
            type="TOOL",
            name=t,
            version="1.0",
            state="ACTIVE",
            provenance={"source": "arhiax-registry"},
        )
        for t in credential.get("permitted_tools", [])
    ]

    return AibomRecord(
        aibom_id=aibom_id,
        agent_id=agent_id,
        name=credential.get("name", ""),
        generated_at=now,
        autonomy_level=credential.get("autonomy_level", "A0"),
        supervisor_id=credential.get("supervisor_id", ""),
        department_id=credential.get("department_id", ""),
        authorization_boundary_id=credential.get("authorization_boundary_id", "default"),
        credential_expires_at=credential.get("credential_expires_at", ""),
        permitted_tools=credential.get("permitted_tools", []),
        permitted_operations=credential.get("permitted_operations", []),
        permitted_data_scopes=credential.get("permitted_data_scopes", []),
        security_profile=credential.get("security_profile", {}),
        components=components,
        controls_active=["C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C11"],
    )


class PromoteRequest(BaseModel):
    target_level: str
    gates: dict
    justification: str = ""


@app.get("/v1/agents/{agent_id}/aibom", response_model=AibomRecord)
async def get_aibom(agent_id: str):
    """Genera el AI Bill of Materials (AIBOM) del agente — control C12 / ABO-C01."""
    credential = await _get(f"{AIM_URL}/v1/credentials/{agent_id}")
    return _build_aibom(credential)


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

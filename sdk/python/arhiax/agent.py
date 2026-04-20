"""ARHIAXAgent — Clase base para agentes gobernados bajo estándar ARHIAX.

Todo agente que herede de ARHIAXAgent queda automáticamente gobernado:
- Cada tool call pasa por el Gateway antes de ejecutarse
- Cada invocación de modelo pasa por evaluación de política
- Toda desviación conductual se registra en BBR
- Las acciones de alto impacto abren tickets HIC automáticamente
- Las violaciones lanzan excepciones específicas auditables
"""
from __future__ import annotations

import asyncio
import functools
import os
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from .client import AIMClient, BBRClient, GatewayClient, HICClient
from .exceptions import (
    ARHIAXCredentialExpired,
    ARHIAXDenied,
    ARHIAXEscalated,
    ARHIAXInjectionDetected,
    ARHIAXToolNotPermitted,
)
from .models import Credential, DecisionOutcome, GovernanceDecision


def governed_tool(
    action: str = "toolCall",
    resource: Optional[str] = None,
    severity: str = "MEDIUM",
    autonomy_level: str = "A1",
):
    """Decorador que envuelve un método con gobernanza ARHIAX automática.

    Uso:
        @governed_tool(action="toolCall", resource="send_email")
        async def send_email(self, to: str, subject: str) -> dict:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        fn._arhiax_governed = True
        fn._arhiax_action = action
        fn._arhiax_resource = resource or fn.__name__
        fn._arhiax_severity = severity
        fn._arhiax_autonomy = autonomy_level

        @functools.wraps(fn)
        async def wrapper(self: "ARHIAXAgent", *args, **kwargs):
            tool_resource = fn._arhiax_resource

            # Verificar que la herramienta está permitida en la credencial
            if self.credential and self.credential.permitted_tools:
                if tool_resource not in self.credential.permitted_tools and "*" not in self.credential.permitted_tools:
                    raise ARHIAXToolNotPermitted(
                        self.agent_id, tool_resource, self.credential.permitted_tools
                    )

            # Evaluar con Gateway
            decision = await self._evaluate_action(
                action=fn._arhiax_action,
                resource=tool_resource,
                context={
                    "operationType": "toolCall",
                    "toolName": tool_resource,
                    "params": kwargs,
                    "requestedAutonomyLevel": fn._arhiax_autonomy,
                },
            )

            self._handle_decision(decision, fn._arhiax_action, tool_resource, fn._arhiax_severity)

            # Ejecutar la herramienta y registrar observación
            start = time.monotonic()
            result = await fn(self, *args, **kwargs)
            elapsed_ms = (time.monotonic() - start) * 1000

            await self._record_observation(
                operation_type="toolCall", duration_ms=elapsed_ms,
                outcome=decision.outcome.value, tool_name=tool_resource,
            )
            return result

        return wrapper
    return decorator


class ARHIAXAgent:
    """Clase base para agentes gobernados bajo estándar ARHIAX.

    Subclasifica esta clase para crear un agente gobernado:

        class MiAgente(ARHIAXAgent):
            agent_id = "agent-abc123"
            gateway_url = "http://localhost:8080"

            @governed_tool(resource="buscar_datos")
            async def buscar_datos(self, query: str) -> list:
                # ARHIAX evalúa esta llamada antes de ejecutar
                return await mi_api.buscar(query)

            async def run(self, task: str):
                response = await self.invoke_model(prompt=task)
                return response
    """

    # Configuración — puede sobreescribirse en subclase o en instancia
    agent_id: str = ""
    gateway_url: str = ""
    aim_url: str = ""
    hic_url: str = ""
    bbr_url: str = ""
    autonomy_level: str = "A0"

    def __init__(
        self,
        credential: Optional[Dict[str, Any]] = None,
        gateway_url: Optional[str] = None,
        aim_url: Optional[str] = None,
        hic_url: Optional[str] = None,
        bbr_url: Optional[str] = None,
    ):
        # URLs desde constructor, atributos de clase, o variables de entorno
        gw = gateway_url or self.gateway_url or os.getenv("ARHIAX_GATEWAY_URL", "http://localhost:8080")
        aim = aim_url or self.aim_url or os.getenv("ARHIAX_AIM_URL", "http://localhost:8200")
        hic = hic_url or self.hic_url or os.getenv("ARHIAX_HIC_URL", "http://localhost:8203")
        bbr = bbr_url or self.bbr_url or os.getenv("ARHIAX_BBR_URL", "http://localhost:8202")

        self._gateway = GatewayClient(gw)
        self._aim = AIMClient(aim)
        self._hic = HICClient(hic)
        self._bbr = BBRClient(bbr)

        self.credential: Optional[Credential] = None
        if credential:
            self.credential = Credential(**credential)
            if self.credential.agent_id:
                self.agent_id = self.credential.agent_id

    # ─── Inicialización ──────────────────────────────────────────────────────

    async def load_credential(self) -> Credential:
        """Carga la credencial desde AIM. Llama esto en startup."""
        if not self.agent_id:
            raise ValueError("agent_id no configurado")
        self.credential = await self._aim.get_credential(self.agent_id)
        if self.credential.lifecycle_state not in ("ACTIVE", "ROTATING"):
            raise ARHIAXCredentialExpired(self.agent_id, self.credential.lifecycle_state)
        self.autonomy_level = self.credential.autonomy_level
        return self.credential

    # ─── Evaluación de acciones ──────────────────────────────────────────────

    async def _evaluate_action(
        self, action: str, resource: str, context: Dict[str, Any]
    ) -> GovernanceDecision:
        return await self._gateway.decide(
            subject=self.agent_id,
            action=action,
            resource=resource,
            context=context,
        )

    def _handle_decision(
        self, decision: GovernanceDecision, action: str, resource: str, severity: str = "MEDIUM"
    ) -> None:
        if decision.outcome == DecisionOutcome.DENY_WITH_INCIDENT:
            raise ARHIAXInjectionDetected(decision.evidence_id)
        if decision.outcome == DecisionOutcome.DENY:
            raise ARHIAXDenied(action, resource, decision.reasons, decision.evidence_id)
        if decision.outcome == DecisionOutcome.ESCALATE_TO_HUMAN:
            ticket_id = decision.hic_ticket_id or ""
            raise ARHIAXEscalated(action, resource, ticket_id)

    async def _open_hic_ticket(
        self, action: str, resource: str, reason: str, severity: str = "MEDIUM", context: dict = {}
    ) -> str:
        return await self._hic.open_ticket(
            agent_id=self.agent_id, action=action, resource=resource,
            reason=reason, severity=severity, context=context,
        )

    async def _record_observation(
        self, operation_type: str, duration_ms: float,
        outcome: str = "ALLOW", tool_name: Optional[str] = None, token_count: int = 0,
    ) -> None:
        await self._bbr.record_observation(
            agent_id=self.agent_id, operation_type=operation_type,
            duration_ms=duration_ms, token_count=token_count,
            outcome=outcome, tool_name=tool_name,
        )

    # ─── Invocación de modelo ────────────────────────────────────────────────

    async def invoke_model(
        self,
        prompt: str,
        model: str = "claude-sonnet-4-6",
        system_prompt: str = "",
        requested_autonomy_level: str = "A1",
    ) -> str:
        decision = await self._evaluate_action(
            action="modelInvoke",
            resource=model,
            context={
                "operationType": "modelInvoke",
                "input": {"prompt": prompt, "system": system_prompt},
                "requestedAutonomyLevel": requested_autonomy_level,
            },
        )
        self._handle_decision(decision, "modelInvoke", model)

        if decision.outcome == DecisionOutcome.ALLOW_WITH_HIC_NOTIFICATION:
            await self._open_hic_ticket(
                action="modelInvoke", resource=model,
                reason="Invocación de modelo de alto impacto",
                severity="HIGH", context={"prompt_length": len(prompt)},
            )

        start = time.monotonic()
        response = await self._call_llm(prompt=prompt, model=model, system_prompt=system_prompt)
        elapsed_ms = (time.monotonic() - start) * 1000

        await self._record_observation(
            operation_type="modelInvoke", duration_ms=elapsed_ms,
            outcome=decision.outcome.value,
            token_count=len(response.split()),
        )
        return response

    async def _call_llm(self, prompt: str, model: str, system_prompt: str = "") -> str:
        """Implementación real de llamada al LLM.
        Sobreescribe este método para integrar con tu proveedor de LLM.
        Por defecto devuelve un placeholder.
        """
        return f"[{model}] Respuesta gobernada para: {prompt[:100]}..."

    # ─── Acceso a datos ──────────────────────────────────────────────────────

    async def access_data(
        self, scope: str, resource: str, operation: str = "read", context: dict = {}
    ) -> GovernanceDecision:
        decision = await self._evaluate_action(
            action="dataAccess",
            resource=resource,
            context={
                "operationType": "dataAccess",
                "dataScope": scope,
                "operation": operation,
                **context,
            },
        )
        self._handle_decision(decision, "dataAccess", resource)
        return decision

    # ─── Llamadas inter-agente ───────────────────────────────────────────────

    async def call_agent(
        self, target_agent_id: str, message: dict, context_chain: List[str] = []
    ) -> GovernanceDecision:
        chain = context_chain or [self.agent_id]
        decision = await self._evaluate_action(
            action="interAgentCall",
            resource=target_agent_id,
            context={
                "operationType": "interAgentCall",
                "contextChain": chain,
                "message": message,
            },
        )
        self._handle_decision(decision, "interAgentCall", target_agent_id)
        return decision

    # ─── Contexto de sesión ──────────────────────────────────────────────────

    async def __aenter__(self) -> "ARHIAXAgent":
        if not self.credential and self.agent_id:
            await self.load_credential()
        return self

    async def __aexit__(self, *args) -> None:
        pass

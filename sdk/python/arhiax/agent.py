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
import inspect
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .client import (
    AIMClient,
    BBRClient,
    CredentialBrokerClient,
    GatewayClient,
    HICClient,
    build_agent_credential_proof,
)
from .dpop import DPoPKey
from .exceptions import (
    ARHIAXCredentialExpired,
    ARHIAXDenied,
    ARHIAXEscalated,
    ARHIAXInjectionDetected,
    ARHIAXToolNotPermitted,
)
from .models import Credential, DecisionOutcome, GovernanceDecision, SecurityProfile


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

            # Un único invocationId atraviesa todo el flujo:
            # gateway (decisión) -> broker (emisión token) -> gateway (confirmación con token) -> evidence store
            invocation_id = str(uuid.uuid4())
            binding = self._build_context_binding(tool_resource, kwargs)

            # Flags reservados que el caller puede inyectar para satisfacer
            # los gates de §13: step_up_satisfied y dual_approval_ticket_id.
            step_up = kwargs.pop("_arhiax_step_up_satisfied", None)
            dual_approval = kwargs.pop("_arhiax_dual_approval_ticket_id", None)
            principal_scopes = (
                list(self.credential.permitted_data_scopes)
                if self.credential and self.credential.permitted_data_scopes
                else None
            )

            base_context = {
                "operationType": "toolCall",
                "toolName": tool_resource,
                "params": self._sanitize_tool_params(kwargs),
                "requestedAutonomyLevel": fn._arhiax_autonomy,
                "severity": fn._arhiax_severity,
                "invocationId": invocation_id,
            }
            if step_up is not None:
                base_context["step_up_satisfied"] = bool(step_up)
            if dual_approval:
                base_context["dual_approval_ticket_id"] = str(dual_approval)
            if principal_scopes:
                base_context["principal_scopes"] = principal_scopes
            # Inyectar campos vinculados (case_id, resource_id, etc.) al contexto plano
            # para que el gateway pueda validarlos contra context_binding del token.
            for key, value in binding.items():
                if key not in {"tool_name", "binding_mode"}:
                    base_context.setdefault(key, value)

            # 1) Decisión inicial (sin token todavía) — autoriza la acción
            decision = await self._evaluate_action(
                action=fn._arhiax_action,
                resource=tool_resource,
                context=base_context,
                invocation_id=invocation_id,
            )

            # 1.b) Si el gateway escala a humano, abrir ticket HIC bloqueante
            #      y re-evaluar con step_up_satisfied (y dual_approval para
            #      CRITICAL) una vez aprobado.
            decision, _hic_ticket_id = await self._resolve_escalate_with_hic(
                action=fn._arhiax_action,
                resource=tool_resource,
                severity=fn._arhiax_severity,
                decision=decision,
                invocation_id=invocation_id,
                base_context=base_context,
            )

            self._handle_decision(decision, fn._arhiax_action, tool_resource, fn._arhiax_severity)

            tool_token = None
            if self.security_profile.enforce_broker_for_tools:
                # 2) Broker emite token efímero vinculado a este invocationId
                tool_token = await self._issue_ephemeral_tool_token(
                    tool_name=tool_resource,
                    requested_autonomy_level=fn._arhiax_autonomy,
                    severity=fn._arhiax_severity,
                    context=kwargs,
                    invocation_id=invocation_id,
                )

                # 3) Confirmación en gateway con el token presente:
                #    el gateway verifica firma, audience, binding, replay y deja
                #    un registro adicional en el evidence store que cierra la cadena
                #    broker -> gateway -> evidence store.
                ephemeral_auth: Dict[str, Any] = {
                    "token": tool_token.token,
                    "jti": tool_token.jti,
                    "audience": tool_token.audience,
                    "scope": tool_token.scope,
                    "issued_at": tool_token.issued_at,
                    "expires_at": tool_token.expires_at,
                    "delegated_by": tool_token.delegated_by,
                }
                if self.security_profile.require_pop:
                    ephemeral_auth["dpop"] = self._dpop_key.make_proof(
                        htm="POST", htu=self._gateway_decide_url,
                    )
                confirm_context = {
                    **base_context,
                    "ephemeralAuth": ephemeral_auth,
                    "brokerTrace": {
                        "jti": tool_token.jti,
                        "proof_key_id": tool_token.proof_key_id,
                        "issued_at": tool_token.issued_at,
                        "expires_at": tool_token.expires_at,
                        "delegated_by": tool_token.delegated_by,
                        "initial_evidence_id": decision.evidence_id,
                    },
                }
                confirmation = await self._evaluate_action(
                    action=fn._arhiax_action,
                    resource=tool_resource,
                    context=confirm_context,
                    invocation_id=invocation_id,
                )
                self._handle_decision(
                    confirmation, fn._arhiax_action, tool_resource, fn._arhiax_severity
                )
                # La confirmación reemplaza la decisión para fines de auditoría posterior
                decision = GovernanceDecision(
                    allow=confirmation.allow,
                    outcome=confirmation.outcome,
                    reasons=confirmation.reasons,
                    obligations=confirmation.obligations,
                    evidence_id=confirmation.evidence_id or decision.evidence_id,
                    hic_ticket_id=confirmation.hic_ticket_id,
                )

            # Ejecutar la herramienta y registrar observación
            start = time.monotonic()
            runtime_kwargs = dict(kwargs)
            signature = inspect.signature(fn)
            accepts_runtime_auth = "_arhiax_runtime_auth" in signature.parameters or any(
                param.kind == inspect.Parameter.VAR_KEYWORD
                for param in signature.parameters.values()
            )
            if accepts_runtime_auth:
                runtime_kwargs["_arhiax_runtime_auth"] = tool_token
            result = await fn(self, *args, **runtime_kwargs)
            elapsed_ms = (time.monotonic() - start) * 1000

            if self.security_profile.sanitize_tool_outputs:
                result = self._sanitize_tool_result(result)

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
    credential_broker_url: str = ""
    autonomy_level: str = "A0"

    def __init__(
        self,
        credential: Optional[Dict[str, Any]] = None,
        gateway_url: Optional[str] = None,
        aim_url: Optional[str] = None,
        hic_url: Optional[str] = None,
        bbr_url: Optional[str] = None,
        credential_broker_url: Optional[str] = None,
        security_profile: Optional[Dict[str, Any]] = None,
    ):
        # URLs desde constructor, atributos de clase, o variables de entorno
        gw = gateway_url or self.gateway_url or os.getenv("ARHIAX_GATEWAY_URL", "http://localhost:8080")
        aim = aim_url or self.aim_url or os.getenv("ARHIAX_AIM_URL", "http://localhost:8200")
        hic = hic_url or self.hic_url or os.getenv("ARHIAX_HIC_URL", "http://localhost:8203")
        bbr = bbr_url or self.bbr_url or os.getenv("ARHIAX_BBR_URL", "http://localhost:8202")
        broker = (
            credential_broker_url
            or self.credential_broker_url
            or os.getenv("ARHIAX_CREDENTIAL_BROKER_URL", "http://localhost:8204")
        )

        self._gateway = GatewayClient(gw)
        self._aim = AIMClient(aim)
        self._hic = HICClient(hic)
        self._bbr = BBRClient(bbr)
        self._credential_broker = CredentialBrokerClient(broker)

        # URL del endpoint /v1/decide del gateway — usada como `htu` en DPoP proofs
        self._gateway_decide_url = f"{gw.rstrip('/')}/v1/decide"
        # Clave DPoP propia del agente (P-256, en memoria)
        self._dpop_key = DPoPKey()

        self.credential: Optional[Credential] = None
        self.security_profile = SecurityProfile(**(security_profile or {}))
        if credential:
            self.credential = Credential(**credential)
            if self.credential.agent_id:
                self.agent_id = self.credential.agent_id
            profile = getattr(self.credential, "security_profile", None)
            if profile:
                self.security_profile = SecurityProfile(**profile)

    # ─── Inicialización ──────────────────────────────────────────────────────

    async def load_credential(self) -> Credential:
        """Carga la credencial desde AIM. Llama esto en startup."""
        if not self.agent_id:
            raise ValueError("agent_id no configurado")
        self.credential = await self._aim.get_credential(self.agent_id)
        if self.credential.lifecycle_state not in ("ACTIVE", "ROTATING"):
            raise ARHIAXCredentialExpired(self.agent_id, self.credential.lifecycle_state)
        self._validate_credential_expiry()
        self.autonomy_level = self.credential.autonomy_level
        profile = getattr(self.credential, "security_profile", None)
        if profile:
            self.security_profile = SecurityProfile(**profile)
        return self.credential

    def _validate_credential_expiry(self) -> None:
        """Validates credential has not expired. Raises ARHIAXCredentialExpired if expired."""
        if not self.credential or not self.credential.credential_expires_at:
            return
        expiry_str = self.credential.credential_expires_at
        if isinstance(expiry_str, str):
            try:
                if expiry_str.endswith('Z'):
                    expiry_dt = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                else:
                    expiry_dt = datetime.fromisoformat(expiry_str)
            except ValueError:
                raise ValueError(f"Invalid credential expiry format: {expiry_str}")
        else:
            expiry_dt = expiry_str
        if expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        now_utc = datetime.now(timezone.utc)
        if now_utc >= expiry_dt:
            raise ARHIAXCredentialExpired(self.agent_id, "EXPIRED")

    # ─── Evaluación de acciones ──────────────────────────────────────────────

    async def _evaluate_action(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
        invocation_id: Optional[str] = None,
    ) -> GovernanceDecision:
        return await self._gateway.decide(
            subject=self.agent_id,
            action=action,
            resource=resource,
            context=context,
            invocation_id=invocation_id,
        )

    async def _issue_ephemeral_tool_token(
        self,
        *,
        tool_name: str,
        requested_autonomy_level: str,
        severity: str,
        context: Dict[str, Any],
        invocation_id: str,
    ):
        ttl_seconds = (
            self.security_profile.high_risk_token_ttl_seconds
            if severity.upper() in {"HIGH", "CRITICAL"}
            else self.security_profile.tool_token_ttl_seconds
        )
        audience = tool_name
        allowed = self.security_profile.allowed_audiences
        if allowed and audience not in allowed and "*" not in allowed:
            raise ARHIAXDenied("toolCall", tool_name, [f"AUDIENCE_NOT_ALLOWED:{audience}"], "")
        dpop_jwk = (
            self._dpop_key.public_jwk if self.security_profile.require_pop else None
        )
        context_binding = self._build_context_binding(tool_name, context)
        parent_hmac = self.credential.parent_chain_hmac if self.credential else None
        agent_proof = (
            build_agent_credential_proof(
                parent_chain_hmac=parent_hmac,
                agent_id=self.agent_id,
                tool_name=tool_name,
                audience=audience,
                scope=f"tool:execute:{tool_name}",
                invocation_id=invocation_id,
                context_binding=context_binding,
                ttl_seconds=ttl_seconds,
                requested_autonomy_level=requested_autonomy_level,
            )
            if parent_hmac
            else None
        )
        return await self._credential_broker.issue_tool_token(
            agent_id=self.agent_id,
            tool_name=tool_name,
            audience=audience,
            scope=f"tool:execute:{tool_name}",
            invocation_id=invocation_id,
            context_binding=context_binding,
            ttl_seconds=ttl_seconds,
            requested_autonomy_level=requested_autonomy_level,
            dpop_jwk=dpop_jwk,
            agent_credential_proof=agent_proof,
        )

    def _build_context_binding(self, tool_name: str, context: Dict[str, Any]) -> Dict[str, str]:
        binding = {"tool_name": tool_name, "binding_mode": self.security_profile.context_binding_mode}
        for key in ("case_id", "property_id", "transaction_id", "resource_id"):
            value = context.get(key)
            if value is not None:
                str_value = str(value).strip()
                if not str_value:
                    raise ValueError(f"context_binding {key} cannot be empty")
                if isinstance(value, (str, int, float)):
                    binding[key] = str_value
                else:
                    raise TypeError(f"context_binding {key} must be string/number, got {type(value).__name__}")
        return binding

    def _sanitize_tool_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        def _sanitize_value(value: Any, key: str = "") -> Any:
            key_low = key.lower()
            if any(marker in key_low for marker in ("token", "authorization", "cookie", "secret", "password")):
                return "[REDACTED]"
            if isinstance(value, dict):
                return {k: _sanitize_value(v, k) for k, v in value.items()}
            if isinstance(value, list):
                return [_sanitize_value(item, key) for item in value]
            if isinstance(value, tuple):
                return tuple(_sanitize_value(item, key) for item in value)
            if isinstance(value, str):
                if any(pattern in value.lower() for pattern in ("authorization:", "bearer ", "set-cookie:", "api_key", "secret=")):
                    return "[REDACTED]"
            return value
        cleaned = {}
        for key, value in params.items():
            cleaned[key] = _sanitize_value(value, key)
        return cleaned

    def _sanitize_tool_result(self, result: Any) -> Any:
        if isinstance(result, dict):
            sanitized = {}
            for key, value in result.items():
                low = key.lower()
                if any(marker in low for marker in ("token", "authorization", "cookie", "secret", "password")):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize_tool_result(value)
            return sanitized
        if isinstance(result, list):
            return [self._sanitize_tool_result(item) for item in result]
        if isinstance(result, str) and any(
            marker in result.lower() for marker in ("authorization:", "bearer ", "set-cookie:", "api_key")
        ):
            return "[REDACTED_TOOL_OUTPUT]"
        return result

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

    async def _await_hic_resolution(self, ticket_id: str) -> str:
        """Bloquea hasta que HIC marque el ticket como APPROVED/REJECTED/SLA_EXPIRED.

        Devuelve el status final. Si la espera supera `hic_poll_timeout_seconds`
        se trata como rechazo implicito (status `TIMEOUT`).
        """
        if not ticket_id:
            return "REJECTED"
        deadline = time.monotonic() + self.security_profile.hic_poll_timeout_seconds
        interval = max(0.1, self.security_profile.hic_poll_interval_seconds)
        while time.monotonic() < deadline:
            status = await self._hic.get_ticket_status(ticket_id)
            if status in {"APPROVED", "REJECTED", "SLA_EXPIRED"}:
                return status
            await asyncio.sleep(interval)
        return "TIMEOUT"

    async def _resolve_escalate_with_hic(
        self,
        *,
        action: str,
        resource: str,
        severity: str,
        decision: GovernanceDecision,
        invocation_id: str,
        base_context: Dict[str, Any],
    ) -> tuple[GovernanceDecision, Optional[str]]:
        """Si la decision escalo a humano, abre ticket HIC y espera resolucion.

        Cuando el ticket se aprueba re-evalua con `step_up_satisfied=True` (y
        `dual_approval_ticket_id` cuando la severidad es CRITICAL).
        Devuelve la decision final (que el caller debe pasar a _handle_decision)
        y el ticket_id usado, por si la herramienta lo necesita en runtime.
        """
        if decision.outcome != DecisionOutcome.ESCALATE_TO_HUMAN:
            return decision, None
        if not self.security_profile.enable_hic_step_up:
            return decision, None

        reason = ",".join(decision.reasons) or "STEP_UP_REQUIRED"
        ticket_id = await self._open_hic_ticket(
            action=action,
            resource=resource,
            reason=reason,
            severity=severity,
            context={
                "invocation_id": invocation_id,
                "initial_evidence_id": decision.evidence_id,
                "reasons": decision.reasons,
            },
        )
        if not ticket_id:
            return decision, None

        status = await self._await_hic_resolution(ticket_id)
        if status != "APPROVED":
            # Mantenemos la decision original (ESCALATE_TO_HUMAN) y propagamos
            # el ticket para que _handle_decision lance ARHIAXEscalated con el
            # ticket_id real. Adicionalmente reemplazamos reasons para reflejar
            # el motivo de cierre.
            failed = GovernanceDecision(
                allow=False,
                outcome=DecisionOutcome.ESCALATE_TO_HUMAN,
                reasons=decision.reasons + [f"HIC_{status}"],
                obligations=decision.obligations,
                evidence_id=decision.evidence_id,
                hic_ticket_id=ticket_id,
            )
            return failed, ticket_id

        # Aprobado: re-evaluar con step-up satisfecho
        enriched = dict(base_context)
        enriched["step_up_satisfied"] = True
        if severity.upper() == "CRITICAL":
            enriched["dual_approval_ticket_id"] = ticket_id
        new_decision = await self._evaluate_action(
            action=action,
            resource=resource,
            context=enriched,
            invocation_id=invocation_id,
        )
        return new_decision, ticket_id

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
        severity: str = "MEDIUM",
    ) -> str:
        if self.credential:
            self._validate_credential_expiry()
        invocation_id = str(uuid.uuid4())
        context_binding = self._build_context_binding("invoke_model", {"model": model})
        base_context = {
            "operationType": "modelInvoke",
            "input": {"prompt": prompt, "system": system_prompt},
            "requestedAutonomyLevel": requested_autonomy_level,
            "severity": severity,
            "invocationId": invocation_id,
            "contextBinding": context_binding,
        }
        decision = await self._evaluate_action(
            action="modelInvoke",
            resource=model,
            context=base_context,
            invocation_id=invocation_id,
        )
        decision, _ = await self._resolve_escalate_with_hic(
            action="modelInvoke",
            resource=model,
            severity=severity,
            decision=decision,
            invocation_id=invocation_id,
            base_context=base_context,
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
        self,
        target_agent_id: str,
        message: dict,
        context_chain: List[str] = [],
        severity: str = "MEDIUM",
    ) -> GovernanceDecision:
        """Llama a otro agente vía token-exchange RFC 8693.

        Flujo: decide inicial → broker emite token con `act_chain` anidado y
        `cnf.jkt` para DPoP → confirmación con token y proof. La cadena `act`
        permite a `target_agent_id` saber quién(es) delegaron la operación.
        """
        invocation_id = str(uuid.uuid4())
        chain = context_chain or [self.agent_id]
        # Si self.agent_id no encabeza la cadena, lo agregamos al frente
        if chain[0] != self.agent_id:
            chain = [self.agent_id, *chain]

        base_context: Dict[str, Any] = {
            "operationType": "interAgentCall",
            "contextChain": chain,
            "message": message,
            "requestedAutonomyLevel": self.autonomy_level or "A1",
            "severity": severity,
            "invocationId": invocation_id,
        }

        # 1) Decisión inicial
        decision = await self._evaluate_action(
            action="interAgentCall",
            resource=target_agent_id,
            context=base_context,
            invocation_id=invocation_id,
        )
        decision, _ = await self._resolve_escalate_with_hic(
            action="interAgentCall",
            resource=target_agent_id,
            severity=severity,
            decision=decision,
            invocation_id=invocation_id,
            base_context=base_context,
        )
        self._handle_decision(decision, "interAgentCall", target_agent_id, severity)

        # 2) Si el perfil exige broker, emite token delegado para el agente B
        if not self.security_profile.enforce_broker_for_tools:
            return decision

        audience = f"agent:{target_agent_id}"
        dpop_jwk = self._dpop_key.public_jwk if self.security_profile.require_pop else None
        ttl_seconds = (
            self.security_profile.high_risk_token_ttl_seconds
            if severity.upper() in {"HIGH", "CRITICAL"}
            else self.security_profile.tool_token_ttl_seconds
        )
        context_binding = {"tool_name": audience}
        parent_hmac = self.credential.parent_chain_hmac if self.credential else None
        agent_proof = (
            build_agent_credential_proof(
                parent_chain_hmac=parent_hmac,
                agent_id=self.agent_id,
                tool_name=audience,
                audience=audience,
                scope=f"agent:invoke:{target_agent_id}",
                invocation_id=invocation_id,
                context_binding=context_binding,
                ttl_seconds=ttl_seconds,
                requested_autonomy_level=self.autonomy_level or "A1",
            )
            if parent_hmac
            else None
        )
        delegated_token = await self._credential_broker.issue_tool_token(
            agent_id=self.agent_id,
            tool_name=audience,
            audience=audience,
            scope=f"agent:invoke:{target_agent_id}",
            invocation_id=invocation_id,
            context_binding=context_binding,
            ttl_seconds=ttl_seconds,
            requested_autonomy_level=self.autonomy_level or "A1",
            dpop_jwk=dpop_jwk,
            act_chain=chain,
            agent_credential_proof=agent_proof,
        )

        # 3) Confirmación con token + DPoP (mismo patrón que governed_tool)
        ephemeral_auth: Dict[str, Any] = {
            "token": delegated_token.token,
            "jti": delegated_token.jti,
            "audience": delegated_token.audience,
            "scope": delegated_token.scope,
            "issued_at": delegated_token.issued_at,
            "expires_at": delegated_token.expires_at,
            "delegated_by": delegated_token.delegated_by,
        }
        if self.security_profile.require_pop:
            ephemeral_auth["dpop"] = self._dpop_key.make_proof(
                htm="POST", htu=self._gateway_decide_url,
            )
        confirm_context = {
            **base_context,
            "toolName": audience,
            "ephemeralAuth": ephemeral_auth,
            "brokerTrace": {
                "jti": delegated_token.jti,
                "act_chain": chain,
                "initial_evidence_id": decision.evidence_id,
            },
        }
        confirmation = await self._evaluate_action(
            action="interAgentCall",
            resource=audience,
            context=confirm_context,
            invocation_id=invocation_id,
        )
        self._handle_decision(confirmation, "interAgentCall", audience, severity)
        return GovernanceDecision(
            allow=confirmation.allow,
            outcome=confirmation.outcome,
            reasons=confirmation.reasons,
            obligations=confirmation.obligations,
            evidence_id=confirmation.evidence_id or decision.evidence_id,
            hic_ticket_id=confirmation.hic_ticket_id,
        )

    # ─── Contexto de sesión ──────────────────────────────────────────────────

    async def __aenter__(self) -> "ARHIAXAgent":
        if not self.credential and self.agent_id:
            await self.load_credential()
        return self

    async def __aexit__(self, *args) -> None:
        pass

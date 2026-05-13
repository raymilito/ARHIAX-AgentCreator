# ARHIAX AgentCreator

Fabrica corporativa de agentes de IA gobernados bajo estandar ARHIAX.

ARHIAX AgentCreator crea agentes que nacen con identidad, autonomia, politicas, auditoria, aprobacion humana y una capa nativa de seguridad para tokens efimeros. La premisa es simple: un agente no debe recibir gobernanza como parche posterior; debe nacer gobernado y operar dentro de un perimetro verificable desde su primera accion.

## Que incluye esta version

- Creator API para registrar agentes y entregar codigo bootstrap gobernado.
- AIM Service para identidad, credenciales, ciclo de vida y `security_profile`.
- AUT Service para autonomia A0-A4 y puertas de promocion.
- Gateway como Policy Enforcement Point con OPA, evidencia y validacion de tokens efimeros.
- Credential Broker para emitir tokens ES256 por accion, bound a DPoP, scope, audience, invocationId y contexto.
- Redis para replay protection, revocacion por `jti` e idempotencia segura.
- HIC Service para aprobacion humana bloqueante en operaciones de alto impacto.
- Evidence Store con ledger append-only y cadena HMAC.
- SDK Python con `ARHIAXAgent`, `@governed_tool`, DPoP, mTLS y brokered ephemeral tokens.

## Inicio rapido

```bash
cp .env.example .env

# Genera CA y certificados de servicio para HTTPS/mTLS interno.
bash scripts/generate-certs.sh

docker compose up -d

curl -X POST http://localhost:8300/v1/agents/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MiPrimerAgente",
    "department_id": "dept-operaciones",
    "supervisor_id": "supervisor-humano-001",
    "permitted_tools": ["consultar_datos", "generar_reporte"],
    "permitted_operations": ["modelInvoke", "toolCall", "interAgentCall"],
    "security_profile": {
      "token_mode": "brokered_ephemeral",
      "require_pop": true,
      "tool_token_ttl_seconds": 60,
      "high_risk_token_ttl_seconds": 30,
      "revocation_mode": "redis+jti",
      "zero_token_in_context": true
    }
  }'
```

## Capa de seguridad de tokens efimeros

La nueva capa evita que un token robado sea util como bearer token reutilizable. El token ya no es un secreto amplio que vive en el prompt o en logs; es una autorizacion efimera por accion, vinculada a contexto, prueba criptografica y decision de politica.

Flujo de una herramienta gobernada:

1. El SDK llama al Gateway sin token para evaluar politica inicial.
2. Si la accion requiere HIC, el SDK abre ticket y reevalua solo despues de aprobacion.
3. El SDK solicita al Credential Broker un token efimero para esa herramienta.
4. El Broker consulta AIM, valida estado `ACTIVE`/`ROTATING`, operaciones permitidas, tools permitidas y `agent_credential_hmac`.
5. El Broker emite JWT ES256 con `scope`, `aud`, `jti`, `exp`, `invocation_id`, `context_binding` y `cnf.jkt` DPoP.
6. El SDK confirma la decision en Gateway con `ephemeralAuth` y proof DPoP.
7. El Gateway valida firma via JWKS, audience, expiracion, binding, DPoP, revocacion y replay.
8. Solo entonces se ejecuta la herramienta y se registra evidencia.

Propiedades de seguridad:

- Token TTL corto: 60s por defecto, 30s para alto riesgo.
- DPoP proof-of-possession: el token no sirve sin la clave privada del agente.
- Replay protection por `jti` en Redis con fallback in-memory para dev/tests.
- Revocacion por `jti`.
- mTLS interno entre servicios.
- Zero token in prompt: el token se inyecta en runtime/tool layer, no en contexto LLM.
- Idempotencia segura: el cache incluye fingerprint del payload para no bloquear reevaluaciones HIC.

## Arquitectura resumida

```text
Developer
  |
  v
Creator API (:8300)
  |-- AIM (:8200) identidad, credential, security_profile
  |-- AUT (:8201) autonomia A0-A4
  |
  v
Agente SDK
  |-- Gateway (:8080) decision inicial
  |-- HIC (:8203) step-up humano si aplica
  |-- Credential Broker (:8204) token efimero ES256 + DPoP
  |-- Gateway (:8080) confirmacion con ephemeralAuth
  |-- Tool runtime
  |-- BBR (:8202) observacion conductual
  v
Evidence Store (:8090) ledger HMAC
```

## Servicios

| Servicio | Puerto | Rol |
| --- | ---: | --- |
| `creator-api` | 8300 | Fabrica de agentes gobernados |
| `gateway` | 8080 | Policy Enforcement Point, DPoP/JWT validation, replay, evidencia |
| `credential-broker` | 8204 | Emision de tokens efimeros por accion |
| `aim-service` | 8200 | Identidad, credenciales, lifecycle, `security_profile` |
| `aut-service` | 8201 | Autonomia A0-A4 |
| `bbr-service` | 8202 | Behavioral Baseline Registry |
| `hic-service` | 8203 | Human-in-the-loop checkpoints |
| `evidence-store` | 8090 | Ledger append-only HMAC |
| `opa` | 8181 | Motor de politicas Rego |
| `redis` | 6379 | Replay/revocation/idempotency store |

## SDK: agente gobernado

```python
from arhiax import ARHIAXAgent, governed_tool


class AgenteDeAnalisis(ARHIAXAgent):
    agent_id = "agent-abc123"
    gateway_url = "https://gateway:8080"
    credential_broker_url = "https://credential-broker:8204"

    @governed_tool(resource="consultar_datos", severity="MEDIUM", autonomy_level="A1")
    async def consultar_datos(self, case_id: str) -> dict:
        return {"case_id": case_id, "status": "ok"}
```

Variables relevantes para TLS/mTLS del SDK:

```bash
export ARHIAX_CA_CERT=/certs/ca.crt
export ARHIAX_TLS_CLIENT_CERT=/certs/agent.crt
export ARHIAX_TLS_CLIENT_KEY=/certs/agent.key
export ARHIAX_GATEWAY_URL=https://gateway:8080
export ARHIAX_CREDENTIAL_BROKER_URL=https://credential-broker:8204
```

## Documentacion clave

- `SECURITY.md`: modelo de seguridad, tokens efimeros y checklist pre-produccion.
- `ARCHITECTURE.md`: arquitectura y flujo runtime.
- `DEPLOYMENT.md`: despliegue local/produccion, certificados y variables.
- `API_REFERENCE.md`: endpoints.
- `docs/ADR-ARHIAX-001-Tokens-Efimeros-y-Delegacion-Gobernada.md`: ADR formal de la capa.
- `docs/ARHIAX_Arquitectura_de_Seguridad_Tokens_Efimeros_y_ADR.docx`: version DOCX corporativa.

## Verificacion

```bash
python -m pytest services/gateway/tests services/creator-api/tests services/aim-service/tests -q -W error::DeprecationWarning

PYTHONPATH=sdk/python python -m pytest sdk/python/tests -q
```

## Licencia

ARHIAX AgentCreator - Sinergia Consulting Group.
Sistema de gobernanza y seguridad para agentes IA bajo estandar ARHIAX.

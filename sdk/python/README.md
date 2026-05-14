# ARHIAX SDK - Python

SDK para crear agentes gobernados con ARHIAX. Documento en ASCII.

## Instalacion

```bash
pip install -e sdk/python/
```

## Concepto

Un agente hereda de `ARHIAXAgent` y marca herramientas con `@governed_tool`. El SDK ejecuta el flujo completo:

1. Evalua politica inicial en Gateway.
2. Resuelve HIC step-up si aplica.
3. Construye `agent_credential_proof` firmado por request.
4. Solicita token efimero al Credential Broker.
5. Genera DPoP proof.
6. Confirma en Gateway con `ephemeralAuth`.
7. Ejecuta la herramienta.
8. Registra observacion en BBR.

El token no entra en el prompt ni en el contexto conversacional.

El proof de agente tampoco envia el `parent_chain_hmac` crudo. El SDK firma un mensaje canonico con nonce, timestamp, agente, tool, audience, scope e invocation id.

## Ejemplo

```python
from arhiax import ARHIAXAgent, governed_tool


class MiAgente(ARHIAXAgent):
    agent_id = "agent-abc123"
    gateway_url = "https://gateway:8080"
    aim_url = "https://aim-service:8200"
    hic_url = "https://hic-service:8203"
    bbr_url = "https://bbr-service:8202"
    credential_broker_url = "https://credential-broker:8204"

    @governed_tool(resource="consultar_datos", severity="MEDIUM", autonomy_level="A1")
    async def consultar_datos(self, case_id: str) -> dict:
        return {"case_id": case_id, "status": "ok"}
```

## Variables de entorno

```bash
export ARHIAX_GATEWAY_URL=https://gateway:8080
export ARHIAX_AIM_URL=https://aim-service:8200
export ARHIAX_HIC_URL=https://hic-service:8203
export ARHIAX_BBR_URL=https://bbr-service:8202
export ARHIAX_CREDENTIAL_BROKER_URL=https://credential-broker:8204

export ARHIAX_CA_CERT=/certs/ca.crt
export ARHIAX_TLS_CLIENT_CERT=/certs/agent.crt
export ARHIAX_TLS_CLIENT_KEY=/certs/agent.key
```

Para desarrollo local sin TLS:

```bash
export ARHIAX_TLS_VERIFY=false
```

## SecurityProfile

El perfil llega desde AIM/Creator API o puede pasarse al constructor:

```python
security_profile = {
    "token_mode": "brokered_ephemeral",
    "zero_token_in_context": True,
    "require_pop": True,
    "tool_token_ttl_seconds": 60,
    "high_risk_token_ttl_seconds": 30,
    "revocation_mode": "redis+jti",
    "allowed_audiences": ["consultar_datos"],
    "context_binding_mode": "resource",
    "sanitize_tool_outputs": True,
    "enforce_broker_for_tools": True,
    "enable_hic_step_up": True,
}
```

## Runtime auth para herramientas

Si una herramienta necesita recibir el token de runtime para llamar a un sistema externo, puede aceptar `_arhiax_runtime_auth`. El SDK solo lo pasa si la firma lo acepta.

```python
@governed_tool(resource="api_externa")
async def api_externa(self, resource_id: str, _arhiax_runtime_auth=None):
    token = _arhiax_runtime_auth.token
    return await call_external_api(token=token, resource_id=resource_id)
```

## Context binding

El SDK vincula tokens a contexto cuando detecta:

- `case_id`
- `property_id`
- `transaction_id`
- `resource_id`

El Gateway rechaza el token si el contexto de confirmacion no coincide.

## Inter-agent calls

```python
await agente.call_agent(
    target_agent_id="agent-destino",
    message={"task": "procesar"},
    context_chain=["agent-origen"],
)
```

El Broker emite scope `agent:invoke:{target_agent_id}` y el JWT incluye `act_chain`.

## Excepciones

| Excepcion | Uso |
| --- | --- |
| `ARHIAXDenied` | Politica deniega |
| `ARHIAXEscalated` | Requiere humano |
| `ARHIAXInjectionDetected` | Inyeccion detectada |
| `ARHIAXCredentialExpired` | Credencial no activa |
| `ARHIAXToolNotPermitted` | Tool fuera de `permitted_tools` |
| `ARHIAXServiceUnavailable` | Servicio upstream no disponible |

## Tests

```bash
PYTHONPATH=sdk/python python -m pytest sdk/python/tests -q
```

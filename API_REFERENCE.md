# API Reference - ARHIAX AgentCreator

Documento en ASCII para evitar problemas de encoding.

## Creator API `:8300`

### `POST /v1/agents/create`

Crea un agente gobernado.

Campos principales:

| Campo | Tipo | Req | Descripcion |
| --- | --- | --- | --- |
| `name` | string | yes | Nombre del agente |
| `description` | string | no | Descripcion funcional |
| `department_id` | string | yes | Unidad organizacional |
| `supervisor_id` | string | yes | Supervisor humano |
| `authorization_boundary_id` | string | no | Dominio de confianza |
| `permitted_tools` | string[] | no | Herramientas permitidas |
| `permitted_data_scopes` | string[] | no | Scopes de datos |
| `permitted_operations` | string[] | no | `modelInvoke`, `toolCall`, `dataAccess`, `interAgentCall` |
| `rotation_days` | int | no | Vigencia de credencial |
| `security_profile` | object | no | Perfil de tokens efimeros y seguridad runtime |

Ejemplo de `security_profile`:

```json
{
  "token_mode": "brokered_ephemeral",
  "zero_token_in_context": true,
  "require_pop": true,
  "tool_token_ttl_seconds": 60,
  "high_risk_token_ttl_seconds": 30,
  "revocation_mode": "redis+jti",
  "allowed_audiences": ["consultar_datos"],
  "context_binding_mode": "resource",
  "sanitize_tool_outputs": true,
  "enforce_broker_for_tools": true
}
```

### `GET /v1/agents`

Lista agentes.

### `GET /v1/agents/{agent_id}`

Devuelve credencial, autonomia y gateway.

### `POST /v1/agents/{agent_id}/evaluate`

Evalua una accion sin ejecutarla.

### `POST /v1/agents/{agent_id}/promote`

Solicita promocion A0-A4 con puertas G1-G5.

### `DELETE /v1/agents/{agent_id}`

Da de baja un agente.

## Gateway `:8080`

### `POST /v1/decide`

Evalua una accion. Si `context.ephemeralAuth` existe, valida token efimero.

Campos:

| Campo | Tipo | Req |
| --- | --- | --- |
| `subject` | string | yes |
| `action` | string | yes |
| `resource` | string | yes |
| `context` | object | no |

`context.ephemeralAuth`:

```json
{
  "token": "eyJ...",
  "jti": "jti-...",
  "audience": "consultar_datos",
  "scope": "tool:execute:consultar_datos",
  "dpop": "eyJ..."
}
```

Errores relevantes:

- `401`: token invalido, expirado, revocado o DPoP faltante.
- `403`: `aud`, `invocationId` o `context_binding` no coincide.
- `409`: replay detectado.
- `413`: body mayor a `MAX_REQUEST_BODY_BYTES`.
- `503`: OPA o JWKS no disponible.

### `POST /v1/ephemeral/revoke/{jti}`

Revoca un `jti`. Query opcional: `ttl_seconds`.

### `GET /v1/anomalies`

Snapshot para SIEM: contadores y `jti` vistos desde multiples origenes.

### `GET /metrics`

Metricas Prometheus.

## Credential Broker `:8204`

### `GET /.well-known/jwks.json`

JWKS publica para validar tokens ES256.

### `POST /v1/tokens/tool`

Emite token efimero por accion.

| Campo | Tipo | Req | Descripcion |
| --- | --- | --- | --- |
| `agent_id` | string | yes | Agente solicitante |
| `tool_name` | string | yes | Tool o `agent:{target_agent_id}` |
| `audience` | string | yes | Audience exacto |
| `scope` | string | yes | `tool:execute:{tool}` o `agent:invoke:{id}` |
| `invocation_id` | string | yes | ID de accion |
| `context_binding` | object | no | Binding contextual |
| `ttl_seconds` | int | no | TTL solicitado |
| `requested_autonomy_level` | string | no | A0-A4 |
| `dpop_jwk` | object | no | JWK publica EC P-256 |
| `act_chain` | string[] | no | Cadena de delegacion |
| `agent_credential_proof` | object | yes | Proof firmado por request contra AIM |
| `agent_credential_hmac` | string | no | Compatibilidad legacy; no usar en produccion |

`agent_credential_proof`:

```json
{
  "nonce": "proof-...",
  "ts": 1778688000,
  "signature": "hex-hmac-sha256"
}
```

La firma se calcula sobre un mensaje canonico que incluye `agent_id`, `tool_name`, `audience`, `scope`, `invocation_id`, `nonce` y `ts`.

## AIM Service `:8200`

- `POST /v1/agents/register`
- `GET /v1/credentials/{agent_id}`
- `GET /v1/agents`
- `POST /v1/credentials/{agent_id}/rotate`
- `POST /v1/credentials/{agent_id}/revoke`
- `POST /v1/credentials/{agent_id}/autonomy`
- `GET /v1/credentials/{agent_id}/history`

La credencial incluye `security_profile`.

## AUT Service `:8201`

- `POST /v1/autonomy/register`
- `GET /v1/autonomy/{agent_id}`
- `POST /v1/autonomy/check`
- `POST /v1/autonomy/{agent_id}/promote`
- `POST /v1/autonomy/{agent_id}/degrade`
- `GET /v1/autonomy/{agent_id}/history`

## BBR Service `:8202`

- `POST /v1/baseline/{agent_id}/observe`
- `GET /v1/baseline/{agent_id}`
- `POST /v1/baseline/{agent_id}/score`
- `GET /v1/baseline/{agent_id}/observations`

## HIC Service `:8203`

- `POST /v1/tickets`
- `GET /v1/tickets/{ticket_id}`
- `POST /v1/tickets/{ticket_id}/approve`
- `POST /v1/tickets/{ticket_id}/reject`

## Evidence Store `:8090`

- `POST /v1/evidence`
- `GET /v1/evidence`
- `GET /v1/evidence/verify/chain`
- `GET /v1/head`

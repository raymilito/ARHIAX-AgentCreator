# Creator API

Fabrica de agentes gobernados ARHIAX.

Puerto: `8300`

## Responsabilidad

Creator API es el punto de entrada para crear agentes que nacen gobernados. Orquesta:

1. Registro de identidad en AIM.
2. Registro explicito de autonomia en AUT con nivel inicial A0.
3. Generacion de `security_profile`.
4. Generacion de `bootstrap_config` estructurado.
5. Generacion de `bootstrap_code` con literales Python seguros.

## `POST /v1/agents/create`

Request:

```json
{
  "name": "AgenteDeAnalisis-v1",
  "description": "Agente para analisis de datos",
  "department_id": "dept-analytics",
  "supervisor_id": "supervisor-humano-001",
  "authorization_boundary_id": "boundary-analytics",
  "permitted_tools": ["consultar_db", "generar_reporte"],
  "permitted_data_scopes": ["analytics", "reportes"],
  "permitted_operations": ["modelInvoke", "toolCall", "dataAccess"],
  "initial_autonomy_level": "A0",
  "rotation_days": 90,
  "security_profile": {
    "token_mode": "brokered_ephemeral",
    "require_pop": true,
    "enforce_broker_for_tools": true,
    "zero_token_in_context": true
  }
}
```

Response `201`:

```json
{
  "agent_id": "agent-a1b2c3d4e5f6",
  "name": "AgenteDeAnalisis-v1",
  "credential": {
    "agent_id": "agent-a1b2c3d4e5f6",
    "autonomy_level": "A0",
    "lifecycle_state": "ACTIVE",
    "security_profile": {
      "token_mode": "brokered_ephemeral",
      "enforce_broker_for_tools": true
    }
  },
  "gateway_url": "http://gateway:8080",
  "autonomy_level": "A0",
  "bootstrap_config": {
    "agent_id": "agent-a1b2c3d4e5f6",
    "gateway_url": "http://gateway:8080",
    "credential_broker_url": "http://credential-broker:8204",
    "security_profile": {
      "token_mode": "brokered_ephemeral",
      "zero_token_in_context": true
    }
  },
  "bootstrap_code": "from arhiax import ARHIAXAgent...",
  "status": "READY"
}
```

`bootstrap_code` se genera con literales escapados. Los valores operativos viajan como `bootstrap_config`, evitando interpolacion insegura de nombres o IDs controlados por usuario.

## Otros Endpoints

- `GET /v1/agents`
- `GET /v1/agents/{agent_id}`
- `POST /v1/agents/{agent_id}/evaluate`
- `POST /v1/agents/{agent_id}/promote`
- `DELETE /v1/agents/{agent_id}`
- `GET /healthz`
- `GET /readyz`

`/readyz` verifica conectividad con AIM, AUT y Gateway.

## Variables

| Variable | Default | Uso |
| --- | --- | --- |
| `AIM_URL` | `http://aim-service:8200` | AIM Service |
| `AUT_URL` | `http://aut-service:8201` | AUT Service |
| `GATEWAY_URL` | `http://gateway:8080` | Gateway |
| `HIC_URL` | `http://hic-service:8203` | HIC Service |
| `CREDENTIAL_BROKER_URL` | `http://credential-broker:8204` | Broker de tokens efimeros |

## Validacion

```bash
python -m pytest services/creator-api/tests -q
```

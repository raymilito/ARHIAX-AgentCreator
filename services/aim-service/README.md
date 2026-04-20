# AIM Service — Agent Identity Management

**Gestión de identidad y credenciales de agentes ARHIAX**

Puerto: `8200`

---

## Qué hace

El AIM Service es el registro de identidad de todos los agentes gobernados. Emite credenciales criptográficamente encadenadas (HMAC-SHA256), gestiona su ciclo de vida completo y controla los niveles de autonomía asociados a cada credencial.

Implementa los controles **AIM-C01, AIM-C02 y AIM-C03** del estándar ARHIAX.

---

## Credencial ARHIAX (10 campos)

Cada agente tiene exactamente una credencial activa con estos campos:

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `agent_id` | string | Identificador único generado (`agent-{hex12}`) |
| `name` | string | Nombre descriptivo del agente |
| `supervisor_id` | string | ID del supervisor humano responsable |
| `department_id` | string | Unidad organizacional |
| `authorization_boundary_id` | string | Dominio de confianza |
| `autonomy_level` | string | Nivel actual: A0–A4 |
| `credential_issued_at` | ISO-8601 | Fecha de emisión |
| `credential_expires_at` | ISO-8601 | Fecha de expiración |
| `rotation_policy` | string | Política de rotación (ej. `"90d"`) |
| `lifecycle_state` | string | `ACTIVE`, `ROTATING`, `SUSPENDED`, `RETIRED` |
| `parent_chain_hmac` | string | HMAC de la cadena de identidad parental |
| `permitted_tools` | string[] | Herramientas autorizadas |
| `permitted_data_scopes` | string[] | Scopes de datos autorizados |
| `permitted_operations` | string[] | Operaciones permitidas |

---

## Endpoints

### `POST /v1/agents/register`

Registra un nuevo agente y emite su credencial inicial.

- El `agent_id` es generado automáticamente
- El `autonomy_level` siempre inicia en `A0` independientemente del solicitado
- El `parent_chain_hmac` se calcula como `HMAC-SHA256(secret, "agent_id:supervisor_id:issued_at")`

---

### `GET /v1/credentials/{agent_id}`

Devuelve la credencial completa del agente.

---

### `GET /v1/agents`

Lista todos los agentes con sus metadatos principales.

---

### `POST /v1/credentials/{agent_id}/rotate`

Rota la credencial del agente:
- Genera nuevas fechas de emisión y expiración
- Recalcula el HMAC de la cadena
- Mantiene el mismo `agent_id`
- Estado: `ACTIVE`

---

### `POST /v1/credentials/{agent_id}/revoke`

Suspende la credencial del agente:
- Estado: `SUSPENDED`
- El agente no podrá operar hasta que sea reactivado o dado de baja

---

### `POST /v1/credentials/{agent_id}/autonomy`

Actualiza el nivel de autonomía en la credencial. Normalmente llamado por AUT Service tras una promoción.

```json
{
  "autonomy_level": "A1",
  "reason": "Promoción tras 30 días sin incidentes"
}
```

---

### `GET /v1/credentials/{agent_id}/history`

Historial completo de cambios de autonomía del agente.

---

## Ciclo de vida de la credencial

```
REGISTRO
    │
    ▼
  ACTIVE ──────────────────────────────────────►  ROTATING
    │                                               │
    │  revoke()                                     │  rotate complete
    ▼                                               ▼
SUSPENDED                                        ACTIVE
    │
    │  admin decommission
    ▼
RETIRED
```

---

## Variables de entorno

| Variable | Default | Descripción |
|---------|---------|-------------|
| `AIM_HMAC_SECRET` | `arhiax-aim-secret-CHANGE-ME` | Secreto para HMAC de cadena de identidad |
| `AIM_DB_PATH` | `/data/aim.db` | Ruta al archivo SQLite |

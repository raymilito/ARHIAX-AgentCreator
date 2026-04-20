# API Reference — ARHIAX AgentCreator

Referencia completa de todos los endpoints del sistema.

---

## Creator API `:8300`

### `POST /v1/agents/create`
Crea un agente gobernado completo.

| Campo | Tipo | Req | Descripción |
|-------|------|-----|-------------|
| `name` | string | ✓ | Nombre descriptivo del agente |
| `description` | string | | Descripción funcional |
| `department_id` | string | ✓ | Unidad organizacional |
| `supervisor_id` | string | ✓ | ID del supervisor humano |
| `authorization_boundary_id` | string | | Dominio de confianza (default: "default") |
| `permitted_tools` | string[] | | Herramientas permitidas |
| `permitted_data_scopes` | string[] | | Scopes de datos |
| `permitted_operations` | string[] | | Operaciones (default: modelInvoke, toolCall) |
| `rotation_days` | int | | Días hasta expiración (default: 90) |

**Response `201`:** `GovernedAgent`

---

### `GET /v1/agents`
Lista todos los agentes.

**Response `200`:** `Array<{agent_id, name, autonomy_level, lifecycle_state, created_at}>`

---

### `GET /v1/agents/{agent_id}`
Detalles de un agente.

**Response `200`:** `{agent_id, credential, autonomy, gateway_url}`

---

### `POST /v1/agents/{agent_id}/evaluate`
Evalúa una acción sin ejecutarla (modo test).

| Campo | Tipo | Req | Descripción |
|-------|------|-----|-------------|
| `action` | string | ✓ | Tipo de acción |
| `resource` | string | ✓ | Recurso objetivo |
| `context` | object | | Contexto adicional |
| `requested_autonomy_level` | string | | Nivel solicitado (default: A1) |

---

### `POST /v1/agents/{agent_id}/promote`
Promueve el nivel de autonomía.

| Campo | Tipo | Req | Descripción |
|-------|------|-----|-------------|
| `target_level` | string | ✓ | Nivel objetivo (A1–A4) |
| `gates` | object | ✓ | Las 5 puertas (G1–G5: bool) |
| `justification` | string | | Justificación documentada |

---

### `DELETE /v1/agents/{agent_id}`
Da de baja un agente (revoca credencial).

**Query:** `reviewer_id` (string, default: "system")

---

### `GET /healthz` | `GET /readyz`
Health y readiness. `/readyz` verifica AIM, AUT y Gateway.

---

## Gateway `:8080`

### `POST /v1/decide`
Evalúa si un agente puede ejecutar una acción.

| Campo | Tipo | Req | Descripción |
|-------|------|-----|-------------|
| `subject` | string | ✓ | ID del agente |
| `action` | string | ✓ | Tipo: toolCall, modelInvoke, dataAccess, interAgentCall |
| `resource` | string | ✓ | Recurso objetivo |
| `context` | object | | invocationId, operationType, input, requestedAutonomyLevel |

**Response `200`:**
```json
{
  "allow": true,
  "reasons": [],
  "obligations": [{"type": "rate_limit", "value": 100}],
  "evidence_id": "ev-0000001234",
  "error": null
}
```

**Errores:**
- `HTTP 413` — Body supera MAX_REQUEST_BODY_BYTES
- `HTTP 503` — OPA no disponible

---

### `GET /metrics`
Métricas Prometheus.

---

## AIM Service `:8200`

### `POST /v1/agents/register`
Registra un agente y emite credencial inicial (A0).

### `GET /v1/credentials/{agent_id}`
Credencial completa del agente.

### `GET /v1/agents`
Lista todos los agentes.

### `POST /v1/credentials/{agent_id}/rotate`
Rota la credencial manteniendo el `agent_id`.

### `POST /v1/credentials/{agent_id}/revoke`
Suspende la credencial (`lifecycle_state: SUSPENDED`).

### `POST /v1/credentials/{agent_id}/autonomy`
Actualiza el `autonomy_level` en la credencial.

| Campo | Tipo | Req |
|-------|------|-----|
| `autonomy_level` | string | ✓ (A0–A4) |
| `reason` | string | |

### `GET /v1/credentials/{agent_id}/history`
Historial de cambios de autonomía.

---

## AUT Service `:8201`

### `GET /v1/autonomy/{agent_id}`
Nivel actual, umbral sigma y fecha de vigencia.

### `POST /v1/autonomy/check`
Evalúa si una acción está dentro del nivel del agente.

| Campo | Tipo | Req | Descripción |
|-------|------|-----|-------------|
| `agent_id` | string | ✓ | |
| `action` | string | ✓ | Acción a evaluar |
| `requested_level` | string | ✓ | Nivel solicitado |
| `sigma_deviation` | float | | Desviación sigma observada |

**Response:** `{allowed, requires_hil, outcome, reason, effective_level}`

### `POST /v1/autonomy/{agent_id}/promote`
Solicita promoción de nivel. Evalúa 5 puertas.

| Campo | Tipo | Req |
|-------|------|-----|
| `agent_id` | string | ✓ |
| `target_level` | string | ✓ |
| `gates` | object | ✓ |
| `justification` | string | |

### `POST /v1/autonomy/{agent_id}/degrade`
Degrada un nivel. Llamado cuando σ > umbral.

| Campo | Tipo | Req |
|-------|------|-----|
| `agent_id` | string | ✓ |
| `reason` | string | ✓ |
| `sigma_observed` | float | |

### `GET /v1/autonomy/{agent_id}/history`
Historial de eventos de autonomía.

---

## BBR Service `:8202`

### `POST /v1/baseline/{agent_id}/observe`
Registra una observación de comportamiento.

| Campo | Tipo | Req | Descripción |
|-------|------|-----|-------------|
| `agent_id` | string | ✓ | |
| `operation_type` | string | ✓ | toolCall, modelInvoke, dataAccess |
| `tool_name` | string | | Nombre de la herramienta |
| `duration_ms` | float | ✓ | Duración en milisegundos |
| `token_count` | int | | Tokens consumidos |
| `outcome` | string | | ALLOW, DENY, etc. |
| `tags` | string[] | | Etiquetas adicionales |

### `GET /v1/baseline/{agent_id}`
Estadísticas de línea base: mean, std, sample_count, has_baseline.

### `POST /v1/baseline/{agent_id}/score`
Calcula sigma de desviación para operación específica.

| Campo | Tipo | Req |
|-------|------|-----|
| `duration_ms` | float | ✓ |
| `token_count` | int | ✓ |

### `GET /v1/baseline/{agent_id}/observations`
Lista observaciones recientes. `?limit=50`

---

## HIC Service `:8203`

### `POST /v1/tickets`
Crea ticket de aprobación humana.

| Campo | Tipo | Req | Descripción |
|-------|------|-----|-------------|
| `agent_id` | string | ✓ | |
| `action` | string | ✓ | Acción que requiere aprobación |
| `resource` | string | ✓ | Recurso objetivo |
| `reason` | string | ✓ | Por qué se escaló |
| `severity` | string | | CRITICAL, HIGH, MEDIUM, LOW |
| `context` | object | | Datos adicionales para el revisor |
| `decision_id` | string | | ID de evidencia relacionada |

**Response `201`:** Ticket completo con `ticket_id` y `sla_deadline`.

### `GET /v1/tickets/{ticket_id}`
Estado de un ticket.

### `GET /v1/tickets`
Lista tickets. `?agent_id=&status=&limit=`

### `POST /v1/tickets/{ticket_id}/approve`
Aprobación humana.

| Campo | Tipo | Req |
|-------|------|-----|
| `approved` | bool | ✓ |
| `reviewer_id` | string | ✓ |
| `notes` | string | |

### `POST /v1/tickets/{ticket_id}/reject`
Rechazo humano. Mismos campos que approve.

### `GET /v1/tickets/expired/check`
Marca tickets vencidos por SLA. Ejecutar periódicamente.

---

## Evidence Store `:8090`

### `POST /v1/evidence`
Agrega entrada al ledger.

| Campo | Tipo | Req |
|-------|------|-----|
| `subject` | string | ✓ |
| `action` | string | ✓ |
| `resource` | string | ✓ |
| `context` | object | |
| `decision` | bool | ✓ |
| `reasons` | string[] | |
| `obligations` | array | |

**Response:** `{id, sequence_number, hash, timestamp}`

### `GET /v1/evidence/{id}`
Registro específico por ID.

### `GET /v1/evidence`
Lista registros. `?limit=20&subject=`

### `GET /v1/head`
Cabeza de la cadena: `{sequence, last_hash, entries}`

### `GET /v1/evidence/verify/chain`
Verifica integridad completa de la cadena HMAC.

---

## Códigos de respuesta comunes

| Código | Significado |
|--------|-------------|
| `200` | OK |
| `201` | Creado |
| `400` | Request inválido |
| `404` | No encontrado |
| `413` | Body demasiado grande |
| `502` | Error de servicio upstream |
| `503` | Servicio no disponible |

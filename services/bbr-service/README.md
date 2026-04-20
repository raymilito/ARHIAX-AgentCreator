# BBR Service — Behavioral Baseline Registry

**Registro de línea base conductual y detección de desviación sigma**

Puerto: `8202`

---

## Qué hace

El BBR Service registra observaciones del comportamiento de cada agente (duración de operaciones, tokens consumidos, outcomes) y calcula en tiempo real cuánto se está desviando el agente de su línea base histórica.

Esta desviación se expresa en unidades de desviación estándar (σ). Si el Gateway o el SDK observa que σ_actual > σ_umbral del nivel del agente, la acción se escala automáticamente a revisión humana.

Implementa el control **DTG-C04 (BBR)** del estándar ARHIAX.

---

## Cómo funciona el cálculo de σ

Para cada agente, el BBR mantiene estadísticas corrientes sobre las últimas 200 observaciones:

```
mean_duration = promedio de duración_ms de operaciones
std_duration  = desviación estándar de duración_ms
mean_tokens   = promedio de tokens consumidos
std_tokens    = desviación estándar de tokens

sigma_duration = |duration_actual - mean_duration| / std_duration
sigma_tokens   = |tokens_actual - mean_tokens| / std_tokens

sigma_final = max(sigma_duration, sigma_tokens)
```

El BBR necesita al menos **5 observaciones** para tener una línea base válida. Antes de eso, devuelve `has_baseline: false` y el Gateway usa `ALLOW_WITH_MONITORING`.

---

## Endpoints

### `POST /v1/baseline/{agent_id}/observe`

Registra una observación de comportamiento del agente.

**Request:**
```json
{
  "agent_id": "agent-abc123",
  "operation_type": "toolCall",
  "tool_name": "consultar_db",
  "duration_ms": 245.3,
  "token_count": 0,
  "outcome": "ALLOW",
  "tags": ["analytics", "query"]
}
```

---

### `GET /v1/baseline/{agent_id}`

Estadísticas actuales de la línea base del agente.

**Response:**
```json
{
  "agent_id": "agent-abc123",
  "sigma_deviation": 0.0,
  "sample_count": 47,
  "mean_duration_ms": 230.5,
  "std_duration_ms": 45.2,
  "mean_tokens": 512.0,
  "std_tokens": 89.3,
  "has_baseline": true
}
```

---

### `POST /v1/baseline/{agent_id}/score`

Calcula el sigma de desviación para una operación específica contra la línea base actual.

**Request:**
```json
{
  "duration_ms": 890.0,
  "token_count": 1500
}
```

**Response:** devuelve `BaselineScore` con `sigma_deviation` calculado.

---

### `GET /v1/baseline/{agent_id}/observations`

Lista las últimas N observaciones del agente (default: 50).

---

## Integración con el SDK

El SDK llama automáticamente a BBR después de cada operación exitosa:

```python
# Esto sucede automáticamente dentro de @governed_tool
await self._record_observation(
    operation_type="toolCall",
    duration_ms=elapsed_ms,
    outcome=decision.outcome.value,
    tool_name=tool_name,
)
```

**El BBR es fail-open**: si no está disponible, el Gateway usa `ALLOW_WITH_MONITORING` y no bloquea la operación.

---

## Variables de entorno

| Variable | Default | Descripción |
|---------|---------|-------------|
| `BBR_DB_PATH` | `/data/bbr.db` | Ruta al archivo SQLite |

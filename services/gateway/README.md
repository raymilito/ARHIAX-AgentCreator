# Gateway — Policy Enforcement Point

**Puerta de gobernanza en tiempo real de ARHIAX**

Puerto: `8080`

---

## Qué hace

El Gateway es el Policy Enforcement Point (PEP) del sistema. Todo agente que quiera ejecutar cualquier acción debe pedir permiso al Gateway primero. El Gateway consulta el motor OPA, registra la decisión en el Evidence Store y devuelve el resultado en menos de 30ms.

Implementa los controles **OPA-C01 a OPA-C04** del estándar ARHIAX.

---

## Flujo de una decisión

```
Agente → POST /v1/decide → Gateway
                               │
                               ├─ Verifica tamaño (max 1 MiB)
                               ├─ Detecta inyección en payload
                               ├─ Consulta OPA → decision
                               ├─ Registra en Evidence Store
                               └─ Devuelve {allow, reasons, obligations, evidence_id}
```

---

## Endpoint principal

### `POST /v1/decide`

Evalúa si un agente puede ejecutar una acción.

**Request:**
```json
{
  "subject": "agent-abc123",
  "action": "toolCall",
  "resource": "consultar_base_datos",
  "context": {
    "invocationId": "uuid-v4",
    "operationType": "toolCall",
    "input": {
      "toolName": "consultar_base_datos",
      "params": {"query": "SELECT * FROM ventas"}
    },
    "requestedAutonomyLevel": "A1"
  }
}
```

**Response `200`:**
```json
{
  "allow": true,
  "reasons": [],
  "obligations": [
    {"type": "rate_limit", "value": 100}
  ],
  "evidence_id": "ev-0000001234",
  "error": null
}
```

---

## Tipos de `action`

| Valor | Uso |
|-------|-----|
| `toolCall` | Invocación de herramienta |
| `modelInvoke` | Llamada al modelo LLM |
| `dataAccess` | Acceso a datos |
| `interAgentCall` | Llamada de agente a agente |

---

## Tipos de `obligations`

| Tipo | Valor | Significado |
|------|-------|-------------|
| `rate_limit` | int | Máximo de requests por minuto |
| `audit_log` | string | Nivel de log requerido |

---

## Política de fallos

| Servicio falla | Comportamiento |
|---------------|---------------|
| OPA no disponible | `HTTP 503` — fail-closed, no se permite la acción |
| Evidence Store falla | Se retorna la decisión igual (fail-open en auditoría) |
| Inyección detectada | `allow: false`, `reasons: ["INJECTION_DETECTED"]` |

---

## Métricas Prometheus

Disponibles en puerto `8080/metrics`:

```
arhiax_gateway_decide_total{outcome="allow"}
arhiax_gateway_decide_total{outcome="deny"}
arhiax_gateway_opa_errors_total
arhiax_gateway_evidence_errors_total
```

---

## Variables de entorno

| Variable | Default | Descripción |
|---------|---------|-------------|
| `OPA_URL` | `http://opa:8181` | URL del motor OPA |
| `EVIDENCE_STORE_URL` | `http://evidence-store:8090` | URL del Evidence Store |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Límite de body (1 MiB) |

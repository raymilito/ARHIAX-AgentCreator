# Creator API

**Fábrica de agentes gobernados ARHIAX** — Punto de entrada principal del sistema.

Puerto: `8300`

---

## Qué hace

El Creator API es el único punto de entrada para crear un agente gobernado. Cuando recibe una especificación de agente, orquesta automáticamente todos los servicios necesarios para dejarlo completamente provisionado:

1. Registra la identidad del agente en AIM → obtiene credencial de 10 campos
2. Inicializa su nivel de autonomía en AUT → comienza en A0
3. Genera el código de bootstrap con el SDK listo para usar
4. Devuelve un `GovernedAgent` completo con `agent_id`, credencial y código

---

## Endpoints

### `POST /v1/agents/create`

Crea un agente gobernado completo.

**Request:**
```json
{
  "name": "AgenteDeAnalisis-v1",
  "description": "Agente para análisis de datos de ventas",
  "department_id": "dept-analytics",
  "supervisor_id": "supervisor-humano-001",
  "authorization_boundary_id": "boundary-analytics",
  "permitted_tools": ["consultar_db", "generar_reporte", "enviar_email"],
  "permitted_data_scopes": ["analytics", "reportes"],
  "permitted_operations": ["modelInvoke", "toolCall", "dataAccess"],
  "initial_autonomy_level": "A0",
  "rotation_days": 90
}
```

**Response `201`:**
```json
{
  "agent_id": "agent-a1b2c3d4e5f6",
  "name": "AgenteDeAnalisis-v1",
  "credential": {
    "agent_id": "agent-a1b2c3d4e5f6",
    "autonomy_level": "A0",
    "lifecycle_state": "ACTIVE",
    "credential_issued_at": "2026-04-19T12:00:00Z",
    "credential_expires_at": "2026-07-18T12:00:00Z",
    "..."
  },
  "gateway_url": "http://gateway:8080",
  "autonomy_level": "A0",
  "bootstrap_code": "from arhiax import ARHIAXAgent...",
  "status": "READY"
}
```

---

### `GET /v1/agents`

Lista todos los agentes registrados.

**Response `200`:**
```json
[
  {
    "agent_id": "agent-a1b2c3d4e5f6",
    "name": "AgenteDeAnalisis-v1",
    "autonomy_level": "A0",
    "lifecycle_state": "ACTIVE",
    "created_at": "2026-04-19T12:00:00Z"
  }
]
```

---

### `GET /v1/agents/{agent_id}`

Detalles completos de un agente incluyendo credencial y nivel de autonomía actual.

---

### `POST /v1/agents/{agent_id}/evaluate`

Evalúa una acción hipotética de un agente sin ejecutarla. Útil para testing.

**Request:**
```json
{
  "action": "toolCall",
  "resource": "consultar_db",
  "context": {},
  "requested_autonomy_level": "A1"
}
```

**Response `200`:**
```json
{
  "agent_id": "agent-a1b2c3d4e5f6",
  "action": "toolCall",
  "resource": "consultar_db",
  "decision": {
    "allow": true,
    "reasons": [],
    "evidence_id": "ev-0000000001"
  }
}
```

---

### `POST /v1/agents/{agent_id}/promote`

Solicita promoción de nivel de autonomía. Requiere las 5 puertas en verde.

**Request:**
```json
{
  "target_level": "A1",
  "gates": {
    "G1_performance": true,
    "G2_security": true,
    "G3_business": true,
    "G4_history": true,
    "G5_governance": true
  },
  "justification": "30 días de operación sin incidentes"
}
```

---

### `DELETE /v1/agents/{agent_id}`

Da de baja un agente (revoca su credencial en AIM).

---

### `GET /healthz` | `GET /readyz`

Health y readiness checks. `/readyz` verifica conectividad con AIM, AUT y Gateway.

---

## Variables de entorno

| Variable | Default | Descripción |
|---------|---------|-------------|
| `AIM_URL` | `http://aim-service:8200` | URL del AIM Service |
| `AUT_URL` | `http://aut-service:8201` | URL del AUT Service |
| `GATEWAY_URL` | `http://gateway:8080` | URL del Gateway |
| `HIC_URL` | `http://hic-service:8203` | URL del HIC Service |

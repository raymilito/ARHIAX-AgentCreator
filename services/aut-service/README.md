# AUT Service — Autonomy Management

**Gestión de la Escala de Autonomía Adaptativa A0–A4**

Puerto: `8201`

---

## Qué hace

El AUT Service gestiona los niveles de autonomía de cada agente. Determina si una acción está dentro del rango permitido para el nivel del agente, evalúa las 5 puertas de promoción, registra degradaciones automáticas y mantiene el historial completo de cambios de autonomía.

Implementa los controles **AUT-C01 a AUT-C05** del estándar ARHIAX.

---

## Escala de autonomía

| Nivel | Nombre | Umbral σ | Qué necesita aprobación |
|-------|--------|----------|------------------------|
| **A0** | Inerte | 1.5σ | Toda acción |
| **A1** | Supervisado | 2.0σ | Acciones de alto impacto |
| **A2** | Guiado | 2.5σ | Acciones de impacto medio |
| **A3** | Autónomo | 3.0σ | Solo acciones críticas |
| **A4** | Adaptativo | 3.5σ | Solo excepciones |

---

## Acciones de alto impacto

Las siguientes acciones siempre generan `ALLOW_WITH_HIC_NOTIFICATION` sin importar el nivel:

```
delete, transfer_funds, modify_policy, promote_agent,
revoke_credential, deploy, override_safety,
grant_permission, external_api_write
```

---

## Las 5 puertas de promoción

Para subir de A0 a A1 (y de cualquier nivel al siguiente), las 5 puertas deben estar en `true`:

| Puerta | Criterio |
|--------|---------|
| `G1_performance` | Métricas de desempeño satisfactorias |
| `G2_security` | Sin incidentes de seguridad en ventana de evaluación |
| `G3_business` | Aprobación de unidad de negocio |
| `G4_history` | Sin degradaciones en los últimos 30 días |
| `G5_governance` | Revisión de gobernanza aprobada |

---

## Endpoints

### `GET /v1/autonomy/{agent_id}`

Nivel actual del agente con umbral sigma.

```json
{
  "agent_id": "agent-abc123",
  "current_level": "A0",
  "sigma_threshold": 1.5,
  "effective_since": "2026-04-19T12:00:00Z"
}
```

---

### `POST /v1/autonomy/check`

Evalúa si una acción está permitida para el nivel del agente.

**Request:**
```json
{
  "agent_id": "agent-abc123",
  "action": "consultar_db",
  "requested_level": "A1",
  "sigma_deviation": 0.8
}
```

**Response:**
```json
{
  "allowed": true,
  "requires_hil": false,
  "outcome": "ALLOW",
  "reason": "Dentro de parámetros de autonomía",
  "effective_level": "A0"
}
```

---

### `POST /v1/autonomy/{agent_id}/promote`

Solicita promoción de nivel. Evalúa las 5 puertas y registra el resultado.

Si alguna puerta falla, devuelve qué puertas específicas fallaron:
```json
{
  "promoted": false,
  "failed_gates": ["G4_history", "G5_governance"],
  "gate_descriptions": {
    "G4_history": "Sin degradaciones en los últimos 30 días",
    "G5_governance": "Revisión de gobernanza aprobada"
  }
}
```

---

### `POST /v1/autonomy/{agent_id}/degrade`

Degrada el agente un nivel. Llamado automáticamente cuando σ_observado > σ_umbral.

---

### `GET /v1/autonomy/{agent_id}/history`

Historial completo de eventos de autonomía (promociones y degradaciones).

---

## Variables de entorno

| Variable | Default | Descripción |
|---------|---------|-------------|
| `AUT_DB_PATH` | `/data/aut.db` | Ruta al archivo SQLite |

# HIC Service — Human-in-the-Loop Checkpoints

**Gestión de tickets de aprobación humana con SLA y notificaciones**

Puerto: `8203`

---

## Qué hace

El HIC Service gestiona los tickets de aprobación humana que se generan cuando un agente intenta una acción de alto impacto o cuando su desviación conductual supera el umbral de su nivel de autonomía. Incluye SLA por severidad, notificaciones via webhook configurable y registro completo de decisiones humanas.

Implementa los controles **HIC-C01 a HIC-C05** del estándar ARHIAX.

---

## Cuándo se abre un ticket

| Trigger | Outcome del Gateway | Severidad típica |
|---------|--------------------|--------------------|
| Acción de alto impacto (alto impacto ok) | `ALLOW_WITH_HIC_NOTIFICATION` | HIGH |
| Desviación σ > umbral del nivel | `ESCALATE_TO_HUMAN` | CRITICAL |
| Inyección detectada | `DENY_WITH_INCIDENT` | CRITICAL |

---

## SLA por severidad

| Severidad | Tiempo máximo de respuesta | Si se vence |
|-----------|--------------------------|-------------|
| CRITICAL | 5 minutos | Ticket pasa a `SLA_EXPIRED` |
| HIGH | 15 minutos | Ticket pasa a `SLA_EXPIRED` |
| MEDIUM | 1 hora | Ticket pasa a `SLA_EXPIRED` |
| LOW | 24 horas | Ticket pasa a `SLA_EXPIRED` |

---

## Estados de un ticket

```
PENDING ──── approve() ──► APPROVED
    │
    └───── reject() ───► REJECTED
    │
    └───── SLA vence ──► SLA_EXPIRED
```

---

## Endpoints

### `POST /v1/tickets`

Crea un ticket de aprobación.

**Request:**
```json
{
  "agent_id": "agent-abc123",
  "action": "enviar_email",
  "resource": "smtp-externo",
  "reason": "Acción de alto impacto requiere aprobación",
  "severity": "HIGH",
  "context": {
    "destinatario": "cfo@empresa.com",
    "asunto": "Reporte mensual"
  },
  "decision_id": "ev-0000001234"
}
```

**Response `201`:**
```json
{
  "ticket_id": "hic-a1b2c3d4e5",
  "agent_id": "agent-abc123",
  "status": "PENDING",
  "severity": "HIGH",
  "sla_deadline": "2026-04-19T12:15:00Z",
  "created_at": "2026-04-19T12:00:00Z"
}
```

---

### `GET /v1/tickets/{ticket_id}`

Estado actual de un ticket.

---

### `GET /v1/tickets`

Lista tickets. Parámetros de query: `agent_id`, `status`, `limit`.

```bash
# Ver todos los pendientes
curl "http://localhost:8203/v1/tickets?status=PENDING"

# Ver tickets de un agente específico
curl "http://localhost:8203/v1/tickets?agent_id=agent-abc123"
```

---

### `POST /v1/tickets/{ticket_id}/approve`

El supervisor humano aprueba la acción.

```json
{
  "approved": true,
  "reviewer_id": "supervisor-jose",
  "notes": "Revisado y aprobado. Destinatario verificado."
}
```

---

### `POST /v1/tickets/{ticket_id}/reject`

El supervisor humano rechaza la acción.

---

### `GET /v1/tickets/expired/check`

Verifica y marca tickets vencidos. Llamar periódicamente (cron job o health check).

---

## Notificaciones webhook

Configura `HIC_WEBHOOK_URL` para recibir notificaciones cuando se crea un ticket:

```json
{
  "event": "hic.ticket.created",
  "ticket_id": "hic-a1b2c3d4e5",
  "agent_id": "agent-abc123",
  "action": "enviar_email",
  "severity": "HIGH",
  "reason": "Acción de alto impacto",
  "sla_deadline": "2026-04-19T12:15:00Z",
  "approve_url": "/v1/tickets/hic-a1b2c3d4e5/approve",
  "reject_url": "/v1/tickets/hic-a1b2c3d4e5/reject"
}
```

Compatible con: Slack (incoming webhooks), Microsoft Teams, cualquier webhook HTTP.

---

## Variables de entorno

| Variable | Default | Descripción |
|---------|---------|-------------|
| `HIC_DB_PATH` | `/data/hic.db` | Ruta al archivo SQLite |
| `HIC_WEBHOOK_URL` | `""` | URL webhook de notificación (opcional) |

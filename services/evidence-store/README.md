# Evidence Store — Ledger Inmutable de Decisiones

**Registro criptográfico inmutable de toda decisión de gobernanza ARHIAX**

Puerto: `8090`

---

## Qué hace

El Evidence Store mantiene un ledger append-only en formato JSONL donde cada entrada está encadenada mediante HMAC-SHA256 con la entrada anterior. Esta cadena hace imposible modificar o eliminar un registro sin invalidar toda la cadena posterior, proporcionando un registro forense completo e inalterable de cada decisión de gobernanza.

Implementa los controles **EGA-C01 a EGA-C04** del estándar ARHIAX.

---

## Integridad de la cadena

```
Entrada 1: {datos} → HMAC(prev="0000...0000", entry_json) = H1
Entrada 2: {datos} → HMAC(prev=H1, entry_json) = H2
Entrada 3: {datos} → HMAC(prev=H2, entry_json) = H3
...

Para modificar la entrada 2 sin ser detectado,
un atacante tendría que recalcular H2, H3, H4... hasta el final.
Imposible sin el secreto HMAC.
```

---

## Retención de evidencia (estándar ARHIAX)

| Tier | Tipos | Retención |
|------|-------|-----------|
| Tier 1 | ATT (attestaciones), APR (aprobaciones) | 7 años |
| Tier 2 | LOG (logs), MET (métricas) | 3 años |
| Tier 3 | TST (tests) | 1 año |

---

## Estructura de cada registro

```json
{
  "id": "ev-0000001234",
  "sequence_number": 1234,
  "timestamp": "2026-04-19T12:00:05Z",
  "subject": "agent-abc123",
  "action": "toolCall",
  "resource": "consultar_base_datos",
  "context": {"invocationId": "uuid", "...": "..."},
  "decision": true,
  "reasons": [],
  "obligations": [{"type": "rate_limit", "value": 100}],
  "prev_hash": "sha256:abc123...",
  "entry_hmac": "sha256:def456..."
}
```

---

## Endpoints

### `POST /v1/evidence`

Registra una nueva entrada en el ledger.

```json
{
  "subject": "agent-abc123",
  "action": "toolCall",
  "resource": "consultar_db",
  "context": {},
  "decision": true,
  "reasons": [],
  "obligations": []
}
```

**Response:**
```json
{
  "id": "ev-0000001234",
  "sequence_number": 1234,
  "hash": "sha256:abc...",
  "timestamp": "2026-04-19T12:00:05Z"
}
```

---

### `GET /v1/evidence/{id}`

Recupera un registro específico por ID.

---

### `GET /v1/evidence`

Lista registros recientes. Parámetros: `limit` (default 20), `subject`.

```bash
# Últimas 50 decisiones del agente
curl "http://localhost:8090/v1/evidence?subject=agent-abc123&limit=50"
```

---

### `GET /v1/head`

Estado actual de la cadena: secuencia, último hash, total de entradas.

```json
{"sequence": 1234, "last_hash": "sha256:...", "entries": 1234}
```

---

### `GET /v1/evidence/verify/chain`

Verifica la integridad completa de toda la cadena HMAC desde génesis.

```json
{"valid": true, "entries_checked": 1234}
```

Si hay corrupción:
```json
{"valid": false, "broken_at_sequence": 500, "entries_checked": 500}
```

---

## Variables de entorno

| Variable | Default | Descripción |
|---------|---------|-------------|
| `LEDGER_PATH` | `/data/evidence.jsonl` | Ruta al archivo JSONL |
| `EVIDENCE_HMAC_SECRET` | `arhiax-evidence-secret-CHANGE-ME` | Secreto para cadena HMAC |

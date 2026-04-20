# Política de Seguridad — ARHIAX AgentCreator

---

## Modelo de seguridad

ARHIAX AgentCreator implementa defensa en profundidad con múltiples capas:

### Capa 1 — Identidad (AIM)
- Cada agente tiene credencial con HMAC-SHA256 encadenado
- Las credenciales expiran automáticamente (default: 90 días)
- Los ciclos de vida `SUSPENDED` y `RETIRED` bloquean operación inmediata
- Secreto HMAC **nunca** viaja en requests — solo se usa para verificación

### Capa 2 — Políticas (OPA/Rego)
- **Deny-by-default**: toda acción está bloqueada salvo regla explícita de permiso
- 19 bundles de políticas ARHIAX
- Si OPA no responde → fail-closed (DENY automático)
- Hot-reload de políticas sin downtime

### Capa 3 — Detección de amenazas (Gateway)
- Detección local de patrones de inyección antes de llegar a OPA
- Límite de 1 MiB por request (anti-DoS básico)
- Outcomes diferenciados por tipo de violación

### Capa 4 — Auditoría (Evidence Store)
- Ledger JSONL append-only con cadena HMAC-SHA256
- Imposible modificar un registro sin invalidar toda la cadena posterior
- Verificación de integridad bajo demanda: `GET /v1/evidence/verify/chain`

### Capa 5 — Supervisión humana (HIC)
- Acciones de alto impacto generan notificación humana obligatoria
- SLA por severidad con expiración automática
- Toda decisión humana queda registrada con `reviewer_id`

---

## Secretos — qué cambiar antes de producción

| Variable | Riesgo si no se cambia |
|---------|------------------------|
| `AIM_HMAC_SECRET` | Un atacante podría forjar credenciales HMAC válidas |
| `EVIDENCE_HMAC_SECRET` | Un atacante podría forjar entradas en el ledger sin detección |

**Generar secretos seguros:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Patrones de inyección detectados

El Gateway detecta los siguientes patrones en el payload de los requests antes de evaluar con OPA:

```
"ignore previous"    → Prompt injection clásica
"disregard"          → Variante de prompt injection
"<script>"           → XSS
"javascript:"        → XSS alternativo
"UNION SELECT"       → SQL injection
"DROP TABLE"         → SQL injection destructiva
"'; --"              → SQL injection comentario
"{{"  "}}"           → Template injection
"${"  "$("           → Shell/template injection
"`"                  → Command injection
"%00"  "%0a%0d"      → Null byte / CRLF injection
"\x00" "\x1b"        → Caracteres de control
```

Cuando se detecta una inyección, el outcome es `DENY_WITH_INCIDENT` y se registra en el Evidence Store.

---

## Comunicación entre servicios

En la configuración actual (docker-compose), todos los servicios están en la red interna `arhiax-net`. Los servicios internos (OPA, Evidence Store) no están expuestos en puertos del host.

**Para producción en red compartida**, considera:
- Agregar mutual TLS (mTLS) entre servicios
- Usar un secret manager (HashiCorp Vault, AWS Secrets Manager) en lugar de variables de entorno
- Restringir los puertos expuestos al host a solo el Gateway (8080) y Creator API (8300)

---

## Reporte de vulnerabilidades

Si encuentras una vulnerabilidad de seguridad en ARHIAX AgentCreator:

1. **No abras un issue público**
2. Contacta directamente al equipo de Sinergia Consulting Group
3. Incluye: descripción, pasos para reproducir, impacto potencial

---

## Checklist de seguridad pre-producción

- [ ] Cambiar `AIM_HMAC_SECRET` por valor generado aleatoriamente
- [ ] Cambiar `EVIDENCE_HMAC_SECRET` por valor generado aleatoriamente
- [ ] Configurar `HIC_WEBHOOK_URL` para notificaciones de tickets críticos
- [ ] Verificar que OPA y Evidence Store NO tienen puertos expuestos al exterior
- [ ] Configurar backups automáticos de volúmenes Docker
- [ ] Configurar monitoreo de `/healthz` y `/readyz` de todos los servicios
- [ ] Ejecutar `GET /v1/evidence/verify/chain` en el cron de integridad (cada hora)
- [ ] Revisar y ajustar las políticas OPA en `runtime/bundles/` para tu caso de uso
- [ ] Establecer proceso de rotación de credenciales de agentes (cada 90 días)
- [ ] Documentar quiénes son los `supervisor_id` y sus responsabilidades

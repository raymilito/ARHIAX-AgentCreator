# Guía de Despliegue — ARHIAX AgentCreator

---

## Despliegue local (desarrollo)

### Requisitos
- Docker Desktop 4.x+
- Docker Compose v2
- 2 GB RAM disponibles
- Puertos libres: 8080, 8090, 8181, 8200–8203, 8300

### Pasos

```bash
# 1. Configurar variables de entorno
cp .env.example .env
# Edita .env con tus valores reales

# 2. Levantar todo el stack
docker compose up -d

# 3. Verificar que todos los servicios están saludables
docker compose ps

# 4. Ver logs en tiempo real
docker compose logs -f

# 5. Verificar readiness de cada servicio
curl http://localhost:8300/readyz   # Creator API
curl http://localhost:8080/readyz   # Gateway
curl http://localhost:8200/readyz   # AIM
curl http://localhost:8201/readyz   # AUT
curl http://localhost:8202/readyz   # BBR
curl http://localhost:8203/readyz   # HIC
curl http://localhost:8090/readyz   # Evidence Store
```

### Apagar

```bash
# Apagar preservando datos
docker compose down

# Apagar y eliminar volúmenes (borrar todos los datos)
docker compose down -v
```

---

## Variables de entorno de producción

**Nunca uses los valores por defecto en producción.** Cambia todos los secretos:

```bash
# .env para producción
AIM_HMAC_SECRET=<64 chars random hex>
EVIDENCE_HMAC_SECRET=<64 chars random hex>
HIC_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK
```

Genera secretos seguros:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Despliegue en servidor Linux (sin Kubernetes)

```bash
# Instalar Docker y Docker Compose en Ubuntu 22.04
curl -fsSL https://get.docker.com | sh
apt-get install -y docker-compose-plugin

# Clonar/subir el proyecto
scp -r ARHIAX-AgentCreator/ usuario@servidor:/opt/arhiax/

# En el servidor
cd /opt/arhiax/ARHIAX-AgentCreator
cp .env.example .env
nano .env  # Editar secretos

# Levantar en background
docker compose up -d

# Configurar reinicio automático (ya configurado en docker-compose con restart: unless-stopped)
# Para que Docker arranque con el sistema:
systemctl enable docker
```

---

## Backups de datos

Los datos persistentes están en volúmenes Docker:

```bash
# Listar volúmenes
docker volume ls | grep arhiax

# Backup de todos los volúmenes
for vol in aim-data aut-data bbr-data hic-data evidence-data; do
    docker run --rm \
        -v arhiax-agentcreator_${vol}:/data \
        -v $(pwd)/backups:/backup \
        alpine tar czf /backup/${vol}-$(date +%Y%m%d).tar.gz /data
done

# Restaurar un volumen
docker run --rm \
    -v arhiax-agentcreator_aim-data:/data \
    -v $(pwd)/backups:/backup \
    alpine tar xzf /backup/aim-data-20260419.tar.gz -C /
```

---

## Monitoreo

### Métricas Prometheus

El Gateway expone métricas en `http://localhost:8080/metrics`:

```
arhiax_gateway_decide_total{outcome="allow"}
arhiax_gateway_decide_total{outcome="deny"}
arhiax_gateway_opa_errors_total
arhiax_gateway_evidence_errors_total
```

### Health checks

Todos los servicios exponen `/healthz` y `/readyz`. Puedes monitorizarlos con cualquier herramienta de uptime (Uptime Kuma, Grafana, etc.):

```bash
# Script de verificación rápida
#!/bin/bash
for port in 8080 8090 8200 8201 8202 8203 8300; do
    status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$port/healthz)
    echo "Puerto $port: $status"
done
```

### Verificar integridad del ledger periódicamente

```bash
# Cron job (cada hora)
curl -s http://localhost:8090/v1/evidence/verify/chain | python -m json.tool

# Si "valid": false — investigar inmediatamente
```

---

## Actualización de servicios

```bash
# Reconstruir un servicio específico sin downtime del resto
docker compose build creator-api
docker compose up -d --no-deps creator-api

# Actualizar políticas OPA (sin reiniciar OPA)
# Copia los nuevos bundles a runtime/bundles/
# OPA detecta cambios automáticamente si usa file watch
docker compose restart opa
```

---

## Configuración de webhook HIC para Slack

1. Crear una Slack App en https://api.slack.com/apps
2. Habilitar Incoming Webhooks
3. Obtener URL del webhook
4. Configurar en `.env`:

```bash
HIC_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
```

El mensaje que llega a Slack incluye:
- Agente que lo generó
- Acción que intenta ejecutar
- Severidad y SLA deadline
- URLs directas para aprobar o rechazar

---

## Troubleshooting

### El Gateway devuelve 503

```bash
# Verificar que OPA está sano
curl http://localhost:8181/health

# Ver logs de OPA
docker compose logs opa

# Verificar que los bundles se cargaron
curl http://localhost:8181/v1/policies | python -m json.tool
```

### El Creator API no puede conectarse a AIM

```bash
# Verificar red Docker
docker compose exec creator-api curl http://aim-service:8200/healthz

# Ver logs del AIM
docker compose logs aim-service
```

### Error "permission denied" en SQLite

```bash
# Los volúmenes deben tener permisos correctos
docker compose exec aim-service ls -la /data/
# Si hay problema, el contenedor crea el directorio en startup
docker compose restart aim-service
```

### Cadena HMAC del Evidence Store rota

Esto indica posible tampering. **No reiniciar el Evidence Store** hasta investigar:

```bash
# Verificar la cadena
curl http://localhost:8090/v1/evidence/verify/chain

# Ver qué registro está roto
# {"valid": false, "broken_at_sequence": 500}

# Ver el registro problemático
curl "http://localhost:8090/v1/evidence?limit=10" | python -m json.tool
```

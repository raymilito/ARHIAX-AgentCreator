# Guia de Despliegue - ARHIAX AgentCreator

Documento en ASCII para evitar problemas de encoding en Windows/GitHub.

## Requisitos

- Docker Desktop 4.x o superior.
- Docker Compose v2.
- Python 3.10+ para SDK/tests.
- Puertos libres: 8080, 8090, 8181, 8200-8204, 8300 y 6379.

## Despliegue local

```bash
cp .env.example .env
bash scripts/generate-certs.sh
docker compose up -d
docker compose ps
```

Verificacion:

```bash
curl http://localhost:8300/readyz   # creator-api
curl http://localhost:8080/readyz   # gateway
curl http://localhost:8200/readyz   # aim-service
curl http://localhost:8201/readyz   # aut-service
curl http://localhost:8202/readyz   # bbr-service
curl http://localhost:8203/readyz   # hic-service
curl http://localhost:8204/readyz   # credential-broker
curl http://localhost:8090/readyz   # evidence-store
```

## Despliegue productivo

El codigo no requiere cambios para produccion. Lo pendiente se coloca al momento de desplegar mediante `.env`, secretos y certificados.

```bash
cp .env.production.example .env
# Reemplazar REQUIRED_AT_DEPLOY_* por secretos reales o configurar Vault.
bash scripts/generate-certs.sh
docker compose config --quiet
docker compose up -d
```

Variables minimas obligatorias:

| Variable | Requisito |
| --- | --- |
| `ARHIAX_PRODUCTION` | `true` |
| `AIM_HMAC_SECRET` | secreto real o Vault `arhiax/aim#hmac` |
| `EVIDENCE_HMAC_SECRET` | secreto real o Vault `arhiax/evidence#hmac` |
| `BROKER_REQUIRE_SIGNED_AGENT_PROOF` | `true` |
| `GATEWAY_PUBLIC_URL` | URL que coincide con DPoP `htu` |
| `ARHIAX_REDIS_URL` | Redis persistente |

## Capa de tokens efimeros

La version actual incluye:

- `credential-broker` en `:8204`.
- JWT ES256 con JWKS publica.
- DPoP proof-of-possession.
- Redis para replay protection, revocacion e idempotencia.
- mTLS interno con certificados de servicio.
- Gateway con validacion de `jti`, `aud`, `exp`, `nbf`, `context_binding` y DPoP.

Variables clave:

```bash
ARHIAX_CA_CERT=/certs/ca.crt
ARHIAX_TLS_CLIENT_CERT=/certs/<service>.crt
ARHIAX_TLS_CLIENT_KEY=/certs/<service>.key
ARHIAX_REQUIRE_MTLS=true
ARHIAX_REDIS_URL=redis://redis:6379/0
BROKER_JWKS_URL=https://credential-broker:8204/.well-known/jwks.json
GATEWAY_PUBLIC_URL=https://gateway:8080
AIM_URL=https://aim-service:8200
BROKER_SIGNING_KEY_PATH=/data/broker_signing_key.pem
BROKER_PERSIST_KEY=true
BROKER_REQUIRE_SIGNED_AGENT_PROOF=true
BROKER_AGENT_PROOF_MAX_SKEW_SECONDS=60
```

Checks post-deploy:

```bash
curl http://localhost:8204/.well-known/jwks.json | python -m json.tool
curl http://localhost:8080/metrics | grep arhiax_gateway_jti_store_backend
curl http://localhost:8080/v1/anomalies | python -m json.tool
```

## Secretos de produccion

Nunca usar valores por defecto en produccion.

```bash
AIM_HMAC_SECRET=<64 chars random hex>
EVIDENCE_HMAC_SECRET=<64 chars random hex>
HIC_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK
```

Generar secretos:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Backups

Respaldar estos volumenes:

- `aim-data`
- `aut-data`
- `bbr-data`
- `hic-data`
- `evidence-data`
- `redis-data`
- `broker-keys`

Ejemplo:

```bash
for vol in aim-data aut-data bbr-data hic-data evidence-data redis-data broker-keys; do
  docker run --rm \
    -v arhiax-agentcreator_${vol}:/data \
    -v $(pwd)/backups:/backup \
    alpine tar czf /backup/${vol}-$(date +%Y%m%d).tar.gz /data
done
```

## Monitoreo

Gateway expone metricas en `http://localhost:8080/metrics`:

```text
arhiax_gateway_decide_total
arhiax_gateway_ephemeral_auth_denied_total
arhiax_gateway_replay_blocked_total
arhiax_gateway_revoked_blocked_total
arhiax_gateway_jti_store_backend
arhiax_gateway_anomaly_total
```

Tambien expone snapshot de anomalias:

```bash
curl http://localhost:8080/v1/anomalies | python -m json.tool
```

## Integridad del ledger

```bash
curl http://localhost:8090/v1/evidence/verify/chain | python -m json.tool
```

Si `valid` es `false`, detener cambios operativos y abrir investigacion forense.

## Troubleshooting

### El gateway rechaza DPoP

- Validar que `GATEWAY_PUBLIC_URL` coincida con el `htu` que usa el SDK.
- Validar reloj de contenedores; DPoP usa ventana corta de `iat`.
- Confirmar que el token tiene `cnf.jkt`.

### El broker no emite token

- Validar `AIM_URL`.
- Confirmar que el agente esta `ACTIVE` o `ROTATING`.
- Confirmar que `agent_credential_proof` esta firmado con nonce/timestamp vigentes.
- Confirmar que tool/scope/audience estan permitidos.

### Replay detectado

Es comportamiento esperado si se reutiliza el mismo token. Emitir un token nuevo para cada tool call.

### Alta concurrencia

- SQLite esta configurado con WAL y `busy_timeout` para despliegue ligero.
- Si el entorno supera decenas/cientos de escrituras por segundo, mover AIM, AUT, BBR, HIC y Evidence Store a PostgreSQL o backend administrado.
- Mantener Redis persistente para `jti`, idempotencia y kill-switch.

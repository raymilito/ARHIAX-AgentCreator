# Production Readiness - ARHIAX AgentCreator

Estado objetivo: el repositorio queda listo para commit/push; lo unico pendiente debe resolverse al momento de desplegar mediante variables, secretos, certificados e infraestructura.

## Estado Del Repositorio

| Area | Estado | Evidencia |
| --- | --- | --- |
| Codigo de servicios | LISTO | Tests por servicio y `py_compile` OK |
| Docker Compose | LISTO | `docker compose config --quiet` OK |
| Capa de tokens efimeros | LISTO | Broker, SDK, Gateway, DPoP, replay, revocacion y proof firmado |
| Documentacion canonica | LISTO | `STANDARD-v11.5-MAPPING.md` |
| Auditoria runtime | LISTO | Evidence Store HMAC, `/v1/evidence/verify/chain`, `/v1/compliance/report` |
| Despliegue productivo | PENDIENTE_DE_DESPLIEGUE | Secretos reales, certificados, Vault opcional, Redis persistente, dominio/URLs |

## Inputs Que Solo Se Definen Al Desplegar

Estos valores no deben quedar hardcodeados en el repo:

| Input | Variable / artefacto | Requisito |
| --- | --- | --- |
| Modo produccion | `ARHIAX_PRODUCTION=true` | Obliga rechazo de secretos default en AIM/Evidence |
| Secreto AIM | `AIM_HMAC_SECRET` o Vault `arhiax/aim#hmac` | 64 hex recomendado |
| Secreto Evidence | `EVIDENCE_HMAC_SECRET` o Vault `arhiax/evidence#hmac` | 64 hex recomendado |
| CA interna | `certs/ca.crt` o secret/volume externo | Generada por entorno |
| Certificados mTLS | `certs/*.crt`, `certs/*.key` | No versionar |
| Redis persistente | `ARHIAX_REDIS_URL` | Requerido para replay/revocacion/idempotencia |
| URL publica Gateway | `GATEWAY_PUBLIC_URL` | Debe coincidir con `htu` DPoP |
| JWKS Broker | `BROKER_JWKS_URL` | Alcanzable desde Gateway |
| Proof firmado | `BROKER_REQUIRE_SIGNED_AGENT_PROOF=true` | Obligatorio en produccion |
| Webhook HIC | `HIC_WEBHOOK_URL`, `HIC_WEBHOOK_ALLOWED_HOSTS` | Opcional pero recomendado |

## Gate De Despliegue

Antes de exponer el stack:

```bash
cp .env.production.example .env
# Reemplazar REQUIRED_AT_DEPLOY_* y URLs reales.
bash scripts/generate-certs.sh
docker compose config --quiet
docker compose up -d
docker compose ps
```

Validaciones obligatorias:

```bash
curl http://localhost:8204/.well-known/jwks.json | python -m json.tool
curl http://localhost:8080/metrics | grep arhiax_gateway_jti_store_backend
curl http://localhost:8090/v1/evidence/verify/chain | python -m json.tool
curl http://localhost:8080/v1/anomalies | python -m json.tool
```

Pruebas de seguridad esperadas:

| Prueba | Resultado esperado |
| --- | --- |
| Token sin DPoP | `401` |
| Token con `aud` incorrecto | `403` |
| Reuso de token/JTI | `409` |
| Proof de agente con nonce repetido | `409` |
| Secretos default con `ARHIAX_PRODUCTION=true` | Servicio no arranca |
| Payload `javascript:` o `${...}` | `DENY_WITH_INCIDENT` |

## Limites Declarados

- SQLite con WAL es defendible para despliegue ligero y piloto controlado; alta concurrencia requiere PostgreSQL o almacenamiento administrado.
- Vault esta soportado, pero la activacion depende del entorno de despliegue.
- C09 INTERP Bridge esta presente como referencia v11.5, pero su integracion bloqueante al Gateway queda diferida.
- El crosswalk regulatorio es tecnico-preliminar; no sustituye certificacion legal.

## Criterio De Listo Para Push

- No subir `.env`, secretos, certificados, `.key`, `.pem`, bases SQLite, JSONL de datos ni locks temporales de Office.
- Incluir `STANDARD-v11.5-MAPPING.md`, `.env.production.example`, tests del Broker y documentacion actualizada.
- Mantener `BROKER_REQUIRE_SIGNED_AGENT_PROOF=true` por defecto en compose.
- Commit recomendado: `Harden ARHIAX v11.5 production readiness`.

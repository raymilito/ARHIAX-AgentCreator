# Changelog - ARHIAX AgentCreator

Documento en ASCII.

## [1.2.0] - 2026-05-14

### Nuevo - Hardening v11.5

- Agregado `STANDARD-v11.5-MAPPING.md` con mapeo canonico ARHIA(X) v11.5.
- Agregado `agent_credential_proof` firmado por request para Credential Broker.
- Agregadas pruebas unitarias del Credential Broker.
- Agregado registro explicito de autonomia en AUT via `POST /v1/autonomy/register`.
- Agregado `bootstrap_config` estructurado en Creator API.
- Agregada proteccion contra nonce replay en proof de agente.

### Cambiado

- Credential Broker puede exigir `BROKER_REQUIRE_SIGNED_AGENT_PROOF=true` para produccion.
- Creator API dejo de inicializar AUT por consulta y usa registro explicito.
- Gateway elimino acceso sincrono al event loop en metricas.
- Gateway amplia deteccion de inyeccion temprana para `javascript:` y template injection.
- SQLite usa WAL, timeout y paths dinamicos por entorno en servicios con persistencia local.
- Evidence Store toma `LEDGER_PATH` en runtime y reconstruye indice/secuencia desde el ledger activo.

### Verificado

- `37 passed` en Gateway.
- `7 passed` en Credential Broker.
- `12 passed` en Creator API.
- `15 passed` en AIM.
- `14 passed` en AUT.
- `12 passed` en BBR.
- `13 passed` en HIC.
- `15 passed` en Evidence Store.
- `50 passed` en SDK.
- `docker compose config --quiet` OK.
- `py_compile` OK para servicios y SDK.

## [1.1.0] - 2026-05-13

### Nuevo - Capa de tokens efimeros

- Agregado `credential-broker` para emision de tokens JWT ES256 por accion.
- Agregado JWKS publico en `/.well-known/jwks.json`.
- Agregado DPoP proof-of-possession en SDK y Gateway.
- Agregada validacion de `cnf.jkt`, `htu`, `htm`, `iat`, `jti` y firma ES256.
- Agregada revocacion por `jti`.
- Agregada proteccion anti-replay con Redis y fallback in-memory.
- Agregada deteccion de anomalias para `aud_mismatch`, `dpop_failure`, `jti_multi_source` y `burst_denials`.
- Agregado endpoint `GET /v1/anomalies`.
- Agregado endpoint `POST /v1/ephemeral/revoke/{jti}`.
- Agregado `security_profile` en credenciales AIM y Creator API.
- Agregado `agent_credential_hmac` como prueba AIM inicial para Broker; reemplazado como prueba primaria por `agent_credential_proof` en v1.2.0.
- Agregado soporte TLS/mTLS en SDK y servicios internos.
- Agregado HIC step-up bloqueante en SDK.
- Agregado soporte de `act_chain` para llamadas inter-agente.

### Cambiado

- Gateway valida tokens efimeros con JWKS del Broker.
- Idempotencia del Gateway ahora incluye fingerprint del payload para no bloquear reevaluaciones HIC.
- AIM devuelve credencial completa despues de rotar, revocar o cambiar autonomia.
- FastAPI `on_event` migrado a `lifespan`.
- `datetime.utcnow()` reemplazado por datetime UTC timezone-aware.
- Documentacion actualizada para la nueva capa.

### Verificado

- Validacion inicial en gateway, creator-api y AIM.
- `50 passed` en SDK.
- `py_compile` OK para servicios y SDK.

## [1.0.0] - 2026-04-19

### Lanzamiento inicial

- Creator API para fabrica de agentes gobernados.
- AIM Service para identidad y credenciales.
- AUT Service para autonomia A0-A4.
- BBR Service para linea base conductual.
- HIC Service para aprobacion humana.
- Gateway como Policy Enforcement Point.
- Evidence Store con ledger HMAC.
- SDK Python con `ARHIAXAgent` y `@governed_tool`.
- Runtime OPA/Rego.
- Docker Compose completo.
- Documentacion base.

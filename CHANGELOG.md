# Changelog - ARHIAX AgentCreator

Documento en ASCII.

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
- Agregado `agent_credential_hmac` como prueba AIM para Broker.
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

- `63 passed` en gateway, creator-api y AIM con `DeprecationWarning` como error.
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

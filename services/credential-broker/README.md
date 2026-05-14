# ARHIAX Credential Broker

Servicio de emision de tokens efimeros por accion para agentes ARHIAX.

## Responsabilidad

El Broker reduce el riesgo de bearer-token replay. Emite JWT ES256 de TTL corto, vinculados a:

- agente solicitante (`sub`)
- tool o agente destino (`aud`)
- scope especifico
- `invocation_id`
- `context_binding`
- DPoP `cnf.jkt`
- cadena de delegacion `act_chain` para inter-agent calls

## Validaciones antes de emitir

El endpoint `POST /v1/tokens/tool` consulta AIM y valida:

- agente existente.
- `lifecycle_state` en `ACTIVE` o `ROTATING`.
- `agent_credential_proof` esta firmado por request contra `parent_chain_hmac`.
- nonce no reutilizado y timestamp dentro de ventana.
- operacion permitida.
- tool permitida.
- `scope` y `audience` coinciden con la accion.

## Endpoints

### `GET /healthz`

Health basico.

### `GET /readyz`

Readiness y `kid` activo.

### `GET /.well-known/jwks.json`

JWKS publica para Gateway.

### `POST /v1/tokens/tool`

Emite token efimero.

## Variables

```bash
BROKER_DEFAULT_TTL_SECONDS=60
BROKER_MAX_TTL_SECONDS=300
BROKER_SIGNING_KEY_PATH=/data/broker_signing_key.pem
BROKER_PERSIST_KEY=true
AIM_URL=https://aim-service:8200
ARHIAX_CA_CERT=/certs/ca.crt
ARHIAX_TLS_CLIENT_CERT=/certs/credential-broker.crt
ARHIAX_TLS_CLIENT_KEY=/certs/credential-broker.key
BROKER_REQUIRE_SIGNED_AGENT_PROOF=true
BROKER_AGENT_PROOF_MAX_SKEW_SECONDS=60
```

## Seguridad

- Firma ES256 con EC P-256.
- Clave privada persistente en volumen `broker-keys`.
- No acepta emision sin prueba AIM.
- No acepta HMAC crudo como prueba primaria cuando `BROKER_REQUIRE_SIGNED_AGENT_PROOF=true`.
- No acepta scopes genericos.
- No expone secretos simetricos.

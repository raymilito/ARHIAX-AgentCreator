# Seguridad - ARHIAX AgentCreator

ARHIAX AgentCreator implementa defensa en profundidad para agentes IA. La version actual incorpora una capa de minimizacion de riesgo por tokens efimeros: broker de credenciales, JWT ES256, DPoP, mTLS interno, revocacion por `jti`, replay protection y zero-token-in-prompt.

## Modelo por capas

### Capa 1 - Identidad AIM

- Cada agente tiene una credencial emitida por AIM.
- La credencial incluye `agent_id`, supervisor, departamento, boundary, autonomia, lifecycle, herramientas, operaciones y `security_profile`.
- `lifecycle_state` controla operacion: solo `ACTIVE` y `ROTATING` pueden operar.
- `parent_chain_hmac` funciona como prueba de posesion de credencial frente al Credential Broker.
- Los secretos HMAC se cargan desde Vault si esta disponible, con fallback a variables de entorno.

### Capa 2 - Credential Broker

- El Broker emite tokens efimeros por accion, no tokens amplios de sesion.
- Antes de emitir consulta AIM y valida:
- `agent_id` registrado.
- lifecycle permitido.
- `agent_credential_hmac` correcto.
- operacion autorizada (`toolCall` o `interAgentCall`).
- herramienta o agente destino autorizado.
- `scope` y `audience` alineados con la accion solicitada.

Claims principales del token:

```json
{
  "iss": "arhiax-credential-broker",
  "sub": "agent-abc123",
  "aud": "consultar_datos",
  "scope": "tool:execute:consultar_datos",
  "jti": "jti-...",
  "iat": 1778688000,
  "nbf": 1778688000,
  "exp": 1778688060,
  "cnf": {"jkt": "..."},
  "invocation_id": "...",
  "context_binding": {"tool_name": "consultar_datos", "case_id": "C-001"}
}
```

### Capa 3 - DPoP proof-of-possession

- El SDK genera una clave EC P-256 por agente/proceso.
- El Broker incorpora `cnf.jkt` al token.
- El Gateway exige DPoP proof para cada token bound.
- El proof valida `htm`, `htu`, `iat`, `jti`, firma ES256 y thumbprint JWK.
- Un token robado no sirve sin la clave privada del agente.

### Capa 4 - Gateway

- Valida firma ES256 via JWKS del Broker.
- Rechaza `aud` mismatch, expiracion, `nbf` futuro, scope invalido y context binding mismatch.
- Protege contra replay con `jti`.
- Soporta revocacion por `POST /v1/ephemeral/revoke/{jti}`.
- Detecta prompt/SQL/XSS/template/command injection antes de OPA.
- Registra metricas de anomalicas: `aud_mismatch`, `dpop_failure`, `jti_multi_source`, `burst_denials`.

### Capa 5 - Transporte mTLS

- Servicios internos usan certificados generados por `scripts/generate-certs.sh`.
- `ARHIAX_CA_CERT` habilita verificacion con CA interna.
- `ARHIAX_TLS_CLIENT_CERT` y `ARHIAX_TLS_CLIENT_KEY` habilitan certificado cliente saliente.
- El SDK tambien soporta estas variables para comunicarse con Gateway, AIM, HIC, BBR y Broker.

### Capa 6 - Politicas OPA y HIC

- OPA sigue deny-by-default.
- Operaciones de alto impacto pueden devolver `ESCALATE_TO_HUMAN`.
- El SDK abre ticket HIC, espera resolucion y reevalua con `step_up_satisfied`.
- Para severidad `CRITICAL`, la reevaluacion incluye `dual_approval_ticket_id`.

### Capa 7 - Evidencia y observabilidad

- Evidence Store mantiene ledger append-only con HMAC.
- Gateway registra cada decision y expone metricas Prometheus.
- Se recomienda enviar `/metrics` y `/v1/anomalies` a SIEM.
- No se debe loggear el token completo; solo `jti`, `aud`, `scope`, `agent_id` y evidence id.

## Reglas operativas

- Nunca insertar tokens en prompts, mensajes del modelo o documentos procesados por el agente.
- No usar tokens en query params.
- No compartir secretos simetricos entre microservicios para validar JWT.
- No aceptar `HS256` para tokens efimeros; solo firma asimetrica ES256.
- No delegar la validacion solo al gateway externo; cada servicio critico debe validar lo que consume.
- Usar TTL corto: 60s default y 30s para alto riesgo.
- Revocar por `jti` ante sospecha.

## Variables criticas

| Variable | Uso |
| --- | --- |
| `AIM_HMAC_SECRET` | Emision/verificacion HMAC de credenciales AIM |
| `EVIDENCE_HMAC_SECRET` | Integridad del ledger |
| `BROKER_SIGNING_KEY_PATH` | Clave privada ES256 persistente del Broker |
| `BROKER_PERSIST_KEY` | Persistencia de clave del Broker |
| `BROKER_JWKS_URL` | JWKS que consume Gateway |
| `ARHIAX_REDIS_URL` | Store de replay/revocacion/idempotencia |
| `ARHIAX_CA_CERT` | CA interna para HTTPS |
| `ARHIAX_TLS_CLIENT_CERT` | Certificado cliente mTLS |
| `ARHIAX_TLS_CLIENT_KEY` | Llave cliente mTLS |
| `GATEWAY_PUBLIC_URL` | URL usada como `htu` DPoP |

## Checklist pre-produccion

- [ ] Generar certificados con `scripts/generate-certs.sh`.
- [ ] Reemplazar `AIM_HMAC_SECRET` y `EVIDENCE_HMAC_SECRET`.
- [ ] Montar volumen persistente para `/data/broker_signing_key.pem`.
- [ ] Habilitar Redis persistente para `jti`.
- [ ] Validar `BROKER_JWKS_URL` desde Gateway.
- [ ] Validar `AIM_URL` desde Credential Broker por mTLS.
- [ ] Confirmar que los agentes usan `ARHIAX_CA_CERT`, `ARHIAX_TLS_CLIENT_CERT` y `ARHIAX_TLS_CLIENT_KEY` cuando operan dentro del mesh.
- [ ] Enviar `/metrics` y `/v1/anomalies` al SIEM.
- [ ] Ejecutar `GET /v1/evidence/verify/chain` periodicamente.
- [ ] Prohibir tokens en prompts/logs por politica de desarrollo.
- [ ] Probar replay: reutilizar un `jti` debe devolver `409`.
- [ ] Probar DPoP: token sin proof debe devolver `401`.

## Reporte de vulnerabilidades

No abrir issues publicos para vulnerabilidades. Contactar al equipo de Sinergia Consulting Group con descripcion, pasos de reproduccion, impacto y evidencia tecnica.

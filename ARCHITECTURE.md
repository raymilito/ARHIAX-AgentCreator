# Arquitectura ARHIAX AgentCreator

Documento en ASCII para evitar problemas de encoding.

## Vision general

ARHIAX AgentCreator implementa gobernanza por diseno: los agentes nacen con identidad, autonomia, politica, auditoria, aprobacion humana y autorizacion efimera por accion.

La arquitectura se organiza en tres capas:

1. Capa de creacion: Creator API, AIM y AUT.
2. Capa de operacion: Gateway, OPA, HIC, BBR y Evidence Store.
3. Capa de autorizacion efimera: Credential Broker, DPoP, Redis/JTI y mTLS.

## Diagrama logico

```text
Developer / Operator
  |
  v
Creator API (:8300)
  |-- AIM (:8200)
  |     - identity
  |     - credential
  |     - lifecycle
  |     - security_profile
  |
  |-- AUT (:8201)
  |     - autonomy A0-A4
  |     - promotion gates
  |
  v
Governed Agent + ARHIAX SDK
  |
  |-- Gateway (:8080)
  |     - policy enforcement
  |     - injection screening
  |     - ephemeral token validation
  |
  |-- Credential Broker (:8204)
  |     - ES256 token minting
  |     - AIM authorization
  |     - DPoP binding
  |
  |-- HIC (:8203)
  |     - human step-up
  |
  |-- BBR (:8202)
  |     - behavior observation
  |
  v
Evidence Store (:8090)
  - immutable HMAC ledger

OPA (:8181)
  - Rego policies

Redis (:6379)
  - replay protection
  - jti revocation
  - idempotency cache
```

## Flujo de creacion

```text
Client
  |
  | POST /v1/agents/create
  v
Creator API
  |
  | POST /v1/agents/register
  v
AIM -> credential + security_profile
  |
  | POST /v1/autonomy/register
  v
AUT -> A0 baseline registrado explicitamente
  |
  v
Creator API -> GovernedAgent response + bootstrap code
```

## Flujo runtime con token efimero

```text
ARHIAXAgent.@governed_tool
  |
  | 1. POST /v1/decide without token
  v
Gateway + OPA
  |
  | 2. If ESCALATE_TO_HUMAN: open HIC ticket, wait approval, reevaluate
  v
Credential Broker
  |
  | 3. Validate signed agent proof, AIM lifecycle, operation, tool/scope/audience
  v
JWT ES256 + cnf.jkt
  |
  | 4. POST /v1/decide with ephemeralAuth + DPoP proof
  v
Gateway validation
  |
  | verifies signature, aud, exp, nbf, jti, context_binding, DPoP and replay
  v
Tool runtime
  |
  | records observation
  v
BBR + Evidence Store
```

## Credential Broker

The Broker issues short-lived, action-scoped JWTs. It does not issue broad session tokens.

Token binding dimensions:

- `sub`: requesting agent.
- `aud`: target tool or target agent.
- `scope`: exact action permission.
- `jti`: unique token identifier.
- `invocation_id`: runtime invocation.
- `context_binding`: resource-specific binding.
- `cnf.jkt`: DPoP public key thumbprint.
- `act`: delegation chain for inter-agent calls.

Agent proof:

- `agent_credential_proof` se calcula por request desde el SDK.
- Incluye `nonce`, `ts`, `agent_id`, `tool_name`, `audience`, `scope` e `invocation_id`.
- El Broker rechaza nonces repetidos y timestamps fuera de ventana.
- `agent_credential_hmac` queda como compatibilidad legacy; en produccion se debe exigir `BROKER_REQUIRE_SIGNED_AGENT_PROOF=true`.

## Gateway security responsibilities

Gateway is both Policy Enforcement Point and token verifier:

- screen payloads for injection patterns.
- call OPA for policy decision.
- verify ES256 signature via Broker JWKS.
- verify DPoP proof-of-possession.
- reject expired, future, revoked or replayed tokens.
- enforce `aud` and `context_binding`.
- record evidence.
- emit SIEM-ready metrics.

## SecurityProfile

AIM credentials include `security_profile`. The SDK reads it automatically.

```json
{
  "token_mode": "brokered_ephemeral",
  "zero_token_in_context": true,
  "require_pop": true,
  "tool_token_ttl_seconds": 60,
  "high_risk_token_ttl_seconds": 30,
  "revocation_mode": "redis+jti",
  "allowed_audiences": ["consultar_datos"],
  "context_binding_mode": "resource",
  "sanitize_tool_outputs": true,
  "enforce_broker_for_tools": true,
  "enable_hic_step_up": true
}
```

## Data models

### Credential

```text
Credential
  agent_id
  name
  supervisor_id
  department_id
  authorization_boundary_id
  autonomy_level
  credential_issued_at
  credential_expires_at
  rotation_policy
  lifecycle_state
  parent_chain_hmac
  permitted_tools
  permitted_data_scopes
  permitted_operations
  security_profile
```

### GovernanceDecision

```text
GovernanceDecision
  allow
  outcome
  reasons
  obligations
  evidence_id
  hic_ticket_id
```

Outcomes:

- `ALLOW`
- `ALLOW_WITH_MONITORING`
- `ALLOW_WITH_HIC_NOTIFICATION`
- `DENY`
- `DENY_WITH_INCIDENT`
- `ESCALATE_TO_HUMAN`

## Design principles

| Principle | Implementation |
| --- | --- |
| Governed by design | Agents are created with identity, policy and runtime controls |
| Deny by default | OPA denies unless policy allows |
| Zero token in prompt | Tokens stay in runtime/tool layer |
| Proof of possession | DPoP binds token to private key |
| Least privilege | Token scope is one action |
| Replay resistance | Redis/JTI and DPoP proof JTI |
| Human step-up | HIC for high-risk or critical flows |
| Evidence first | Every decision creates audit trail |
| mTLS internal | Services authenticate over TLS |
| Safe bootstrap | Creator returns `bootstrap_config` and escaped Python literals |
| Production proof | Broker requires signed per-request agent proof |

## Dependencies

| Component | Technology |
| --- | --- |
| API services | Python + FastAPI |
| Policy engine | OPA/Rego |
| Ledger | JSONL + HMAC |
| Replay/revocation | Redis |
| JWT signing | ES256 / P-256 |
| DPoP | RFC 9449 pattern |
| Containers | Docker Compose |

# ARHIAX Security Architecture for Ephemeral Tokens

## Purpose

This document defines the ARHIAX target architecture to minimize the risk of compromise, replay, misuse, and exfiltration of ephemeral tokens across ARHIAX CM, ARHIA-DX, and governed agent runtimes.

The design goal is not only to harden tokens, but to ensure that a leaked token has minimal operational value, cannot be reused outside its intended context, and leaves auditable traces across the control plane.

## Scope

This architecture applies to:

- user-facing web and API clients
- internal microservices
- governed agents and tool execution layers
- cadastral and high-impact transactional operations
- runtime governance, observability, and incident response

## Threat Model

Ephemeral tokens in ARHIAX may include JWT access tokens, delegated OAuth tokens, session-bound API credentials, or short-lived service credentials. The primary threat scenarios are:

- interception in transit through downgraded or compromised network paths
- extraction from logs, memory dumps, traces, or exception payloads
- replay within the valid lifetime of the token
- lateral reuse across internal services that over-trust upstream validation
- misuse by a compromised agent runtime
- exfiltration through prompt injection or tool output leakage
- authorization drift where a valid token is accepted for an operation that should require stronger context

## Security Principles

The ARHIAX architecture for ephemeral credentials is governed by the following principles:

- zero-token-in-context: the LLM never receives operational tokens in prompt or conversation state
- proof-of-possession over bearer by default for external clients and delegated actions
- per-action delegation instead of broad session-wide authority
- independent validation at every trust boundary
- contextual authorization in addition to token validity
- fail-closed behavior on validation, policy, or broker errors
- auditable correlation between token issuance, use, decision, and business object

## Target Architecture

The recommended target pattern is:

```text
User or Calling Service
  -> Identity Provider
  -> API Gateway
  -> Policy Layer
  -> Credential Broker
  -> Purpose-Bound Ephemeral Token
  -> Target Service or Tool
  -> Evidence and Monitoring Plane
```

In ARHIA-DX, the LLM orchestration plane is isolated from the credential plane:

```text
LLM Context Plane
  - system prompt
  - user prompt
  - retrieved documents
  - tool schemas
  - tool results sanitized for model consumption

Credential Plane
  - user identity and session state
  - delegated ephemeral tokens
  - service credentials
  - token exchange and revocation state
```

The LLM may request a tool invocation, but it must never directly observe or manipulate the authorization material used by that tool.

## Core Components

### 1. Identity Provider

The identity provider is responsible for:

- authenticating users and workloads
- issuing signed access tokens
- supporting token exchange or delegated grant patterns
- enforcing short expiration windows
- publishing signing keys with rotation

Recommended options:

- Keycloak for self-managed enterprise control
- Auth0 for managed deployment speed where tenancy and data residency fit

Required characteristics:

- asymmetric signatures only, preferably `ES256` or `EdDSA`
- audience-specific tokens
- refresh token rotation with reuse detection
- support for DPoP where client patterns allow it

### 2. API Gateway

The gateway performs coarse-grained controls:

- initial authentication and signature verification
- request size and schema sanity checks
- rate limiting and anomaly throttling
- early rejection of obvious malicious payloads

The gateway must not be the only validator. Every downstream service remains responsible for independent validation and authorization.

### 3. Credential Broker

The Credential Broker is the central ARHIAX control for ephemeral token minimization.

Responsibilities:

- accept a validated caller identity and requested action
- evaluate whether delegation is allowed
- mint a token for a single tool, service, or operation
- bind that token to possession, audience, and purpose
- emit audit events for issuance, use, and revocation

The broker must never expose long-lived secrets to agents, clients, or downstream services that do not need them.

The broker should issue tokens with:

- `sub`: subject identity
- `act`: actor or delegated caller identity
- `aud`: one target service only
- `scope`: one business action or narrow set of actions only
- `jti`: unique identifier
- `iat`, `nbf`, `exp`: narrow validity window
- `cnf`: proof-of-possession binding where supported
- business correlation claims such as `case_id`, `property_id`, or `transaction_id` when appropriate

### 4. Policy Layer

The policy layer decides whether a valid token should authorize a requested action in the current context.

This includes:

- operation classification by risk
- ownership or delegated authority over the target object
- workflow state validation
- geography, tenancy, and department boundaries
- autonomy constraints for agents
- requirement for step-up authentication or human approval

Recommended implementation:

- OPA for policy evaluation close to runtime
- Cedar as an option where explicit authorization modeling is preferred

### 5. Service Mesh and Workload Identity

For internal service-to-service communication:

- enforce mTLS between workloads
- use workload identity instead of shared secrets
- avoid passing end-user tokens unless the downstream service explicitly requires end-user context

Preferred pattern:

- user token validated at ingress
- downstream services use delegated or exchanged tokens when user context is needed
- otherwise use service identity plus explicit business context

### 6. Evidence and Monitoring Plane

Every issuance and use of an ephemeral token must generate observability signals.

Required telemetry:

- issuance event with `jti`, `sub`, `act`, `aud`, `scope`, TTL, and request origin
- validation outcome per service
- denial reason where applicable
- correlation to business resource or cadastral act
- incident markers for replay, mismatch, or abnormal reuse

## Token Design Standard

ARHIAX ephemeral tokens must comply with the following baseline:

- asymmetric signature only
- `aud` required and exact-match validated
- `iss` required and exact-match validated
- `exp` required with short maximum TTL
- `nbf` required for critical operations
- `jti` required for replay detection and revocation
- `scope` or equivalent fine-grained permission claim required
- proof-of-possession binding strongly preferred

Maximum TTL guidance:

- 30 to 60 seconds for agent tool calls
- 1 to 2 minutes for high-impact mutations
- up to 5 minutes for sensitive read operations
- avoid long-lived broad-scope access tokens for operational actions

## Validation Standard

Each service must validate tokens locally before acting on them.

Minimum validation checks:

- allowed algorithm
- signature
- `iss`
- `aud`
- `exp`
- `nbf` where required
- `jti`
- proof-of-possession confirmation if applicable

Additional business checks:

- resource ownership or delegated authority
- expected workflow state
- correspondence between token claims and request payload
- conformity with autonomy and governance policy

Validation must fail closed. If policy, key retrieval, revocation lookup, or possession proof verification cannot be completed, the operation must be denied.

## Replay Resistance

Replay risk is reduced through layered controls:

- DPoP for compatible external clients
- mTLS-bound tokens for internal high-trust service traffic where feasible
- short expiration windows
- one-time or low-frequency `jti` usage tracking
- idempotency keys for sensitive write operations
- narrow audiences and scopes

DPoP significantly reduces bearer replay risk, but it does not eliminate the need for claim validation, `jti` tracking, and operational anomaly detection.

## Revocation Model

Purely stateless JWT use is insufficient for high-impact ARHIAX operations. The platform should accept limited statefulness for stronger control.

Recommended hybrid revocation pattern:

- local signature and claim validation for normal low-latency paths
- Redis-backed revoked `jti` tracking with TTL aligned to token expiry
- introspection or broker callback for highly sensitive operations
- refresh token rotation with reuse detection for user sessions

This design balances latency with operational control.

## ARHIA-DX and Agent-Specific Controls

### Zero-Token-In-Context

The most important ARHIA-DX rule is:

- no access token, refresh token, API key, signed URL, or privileged session artifact may be inserted into prompt, memory, tool description, chain-of-thought scaffold, retrieved document, or model-visible transcript

### Tool Invocation Pattern

Safe pattern:

1. the model chooses a tool by intent
2. the orchestrator validates the request shape
3. the orchestrator or tool adapter requests a delegated ephemeral token from the Credential Broker
4. the token is attached at runtime to the outbound tool request
5. the tool response is sanitized before returning to the model

Unsafe pattern:

- placing the token in prompt instructions
- including authorization headers in tool input shown to the model
- logging raw tool requests with credentials
- allowing the model to construct arbitrary outbound requests with raw credentials

### Output Sanitization

Tool adapters must scrub:

- authorization headers
- cookies
- signed URLs
- stack traces with secrets
- downstream raw responses containing secret-bearing metadata

The model should receive only the business result needed for reasoning.

## Contextual Authorization for Cadastral Operations

For ARHIAX CM and other sensitive operational domains, token validity alone is not enough. The backend must additionally verify:

- whether the identity is authorized for the specific parcel, case, or cadastral act
- whether the operation is legal in the current workflow state
- whether the operation requires elevated assurance
- whether the request originates from an authorized department, tenant, or workflow role

High-impact actions should support:

- step-up authentication
- explicit confirmation
- dual approval where policy demands it
- idempotency enforcement
- forensic correlation between token `jti` and business act hash

## Logging and Telemetry Standard

Never log raw tokens.

Allowed observability fields:

- `jti`
- `sub`
- `act`
- `aud`
- token class
- TTL bucket
- validation result
- client IP or workload identity
- associated business object identifier

Detection rules should alert on:

- same `jti` seen from multiple IPs or workloads
- token use after expiry
- repeated `aud` mismatches
- proof-of-possession failures
- denied high-risk operations followed by rapid retries
- unusual token issuance volume for a single actor or agent

## Reference Technology Stack

Recommended stack for the target state:

- Identity Provider: Keycloak or Auth0
- Proof-of-Possession: DPoP for compatible clients
- Service-to-Service Security: Istio or Envoy with mTLS
- Credential Broker: dedicated ARHIAX internal service
- Policy Engine: OPA and Rego, optionally Cedar for authorization modeling
- Secrets Management: HashiCorp Vault with short leases and rotation
- Revocation Cache: Redis with TTL-aligned revocation entries
- SIEM and Detection: enterprise SIEM with token anomaly rules

## Phased Implementation Roadmap

### Phase 1: Immediate Hardening

- enforce asymmetric token signing
- validate `iss`, `aud`, `exp`, `nbf`, `jti`, and algorithm in every service
- remove secrets from prompts, logs, traces, and query strings
- shorten token TTLs
- add revoked `jti` tracking and basic anomaly alerts

### Phase 2: Trust Boundary Reinforcement

- deploy mTLS for internal traffic
- adopt DPoP for external clients where supported
- separate user identity from service and agent identity
- classify operations and define narrow scopes

### Phase 3: ARHIAX Delegation Model

- deploy the Credential Broker
- move all agent tool invocations to brokered per-action credentials
- enforce zero-token-in-context across ARHIA-DX
- add output sanitization in tool adapters

### Phase 4: High-Assurance Operations

- add step-up authentication for critical acts
- enforce dual approval where required
- bind token use to business transaction and workflow state
- expand SIEM detections and red-team replay testing

## Non-Negotiable Architectural Requirements

The following requirements should be treated as mandatory for the ARHIAX target state:

- no bearer-only trust model for critical actions
- no raw operational token in any model-visible context
- no single-point validation at the gateway only
- no broad reusable token for multiple cadastral actions
- no production logging of raw tokens or secret-bearing headers

## Conclusion

The ARHIAX-grade solution to ephemeral token risk is not a stronger standalone JWT pattern. It is a governed delegation architecture in which credentials are short-lived, purpose-bound, proof-of-possession aware, independently validated, contextually authorized, isolated from LLM context, and fully traceable across issuance and use.

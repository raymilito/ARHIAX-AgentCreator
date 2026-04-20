# Arquitectura ARHIAX AgentCreator

## Visión general

ARHIAX AgentCreator implementa el principio de **gobernanza por diseño**: los agentes no son supervisados después de crearse, sino que nacen con los mecanismos de gobernanza integrados desde su primer instante de existencia.

El sistema tiene dos capas distintas que trabajan en conjunto:

1. **Capa de creación** — El Creator API y sus servicios de soporte (AIM, AUT) que provisionan el agente
2. **Capa de operación** — El Gateway, OPA, Evidence Store, BBR y HIC que gobiernan cada acción del agente en tiempo de ejecución

---

## Diagrama de arquitectura completo

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                        ARHIAX AgentCreator                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  CAPA DE CREACIÓN                                                          ║
║  ─────────────────────────────────────────────────────────────────         ║
║                                                                            ║
║  Developer / Operador                                                      ║
║       │                                                                    ║
║       │ POST /v1/agents/create                                             ║
║       ▼                                                                    ║
║  ┌─────────────────────────────────────────────────────────────┐           ║
║  │                  Creator API  :8300                         │           ║
║  │                                                             │           ║
║  │  1. Valida AgentSpec (nombre, depto, tools, operaciones)   │           ║
║  │  2. Registra en AIM → obtiene credencial 10 campos         │           ║
║  │  3. Inicializa en AUT → nivel A0                           │           ║
║  │  4. Genera bootstrap code con SDK                          │           ║
║  │  5. Devuelve GovernedAgent {agent_id, credential, code}    │           ║
║  └──────┬─────────────────────────────────────┬───────────────┘           ║
║         │                                     │                           ║
║         ▼                                     ▼                           ║
║  ┌───────────────────┐               ┌──────────────────────┐             ║
║  │   AIM Service     │               │    AUT Service       │             ║
║  │   :8200           │               │    :8201             │             ║
║  │                   │               │                      │             ║
║  │  • Registra agente│               │  • Inicializa A0     │             ║
║  │  • Emite credencial               │  • Guarda umbral σ   │             ║
║  │    (10 campos)    │               │  • Historial niveles │             ║
║  │  • HMAC chain     │               │  • 5 puertas promo.  │             ║
║  │  • SQLite DB      │               │  • SQLite DB         │             ║
║  └───────────────────┘               └──────────────────────┘             ║
║                                                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  CAPA DE OPERACIÓN  (gobernanza en tiempo real)                            ║
║  ─────────────────────────────────────────────────────────────────         ║
║                                                                            ║
║  Agente IA (usando SDK)                                                    ║
║       │                                                                    ║
║       │  @governed_tool → decide(action, resource, context)               ║
║       ▼                                                                    ║
║  ┌─────────────────────────────────────────────────────────────┐           ║
║  │                   Gateway (PEP)  :8080                      │           ║
║  │                                                             │           ║
║  │  1. Recibe POST /v1/decide {subject, action, resource}     │           ║
║  │  2. Verifica tamaño del body (max 1 MiB)                   │           ║
║  │  3. Detecta patrones de inyección en payload               │           ║
║  │  4. Consulta OPA para evaluación de políticas              │           ║
║  │  5. Registra decisión en Evidence Store                    │           ║
║  │  6. Devuelve {allow, reasons, obligations, evidence_id}    │           ║
║  └──────┬────────────────────────────────────┬────────────────┘           ║
║         │                                    │                            ║
║         │ POST /v1/data/arhiax/main          │ POST /v1/evidence          ║
║         ▼                                    ▼                            ║
║  ┌───────────────────┐               ┌──────────────────────┐             ║
║  │   OPA Engine      │               │   Evidence Store     │             ║
║  │   :8181           │               │   :8090              │             ║
║  │                   │               │                      │             ║
║  │  19 bundles Rego  │               │  • JSONL append-only │             ║
║  │  B01 – B19        │               │  • HMAC-SHA256 chain │             ║
║  │  deny-by-default  │               │  • Merkle integrity  │             ║
║  │  Evaluación <5ms  │               │  • Retención tier    │             ║
║  └───────────────────┘               │    T1=7yr T2=3yr T3=1yr           ║
║                                      └──────────────────────┘             ║
║                                                                            ║
║  SDK maneja los outcomes:                                                  ║
║  ┌─────────────────────────────────────────────────────────────┐           ║
║  │                   ARHIAX SDK                                │           ║
║  │                                                             │           ║
║  │  ALLOW              → ejecuta la acción                    │           ║
║  │  ALLOW+MONITORING   → ejecuta + registra en BBR            │           ║
║  │  ALLOW+HIC          → ejecuta + abre ticket HIC            │──────────►║
║  │  DENY               → lanza ARHIAXDenied                   │       ┌──────────────┐
║  │  DENY+INCIDENT      → lanza ARHIAXInjectionDetected        │       │ HIC Service  │
║  │  ESCALATE_TO_HUMAN  → lanza ARHIAXEscalated + ticket HIC   │──────►│ :8203        │
║  └──────────────────────────────────┬──────────────────────────┘       │ Tickets SLA  │
║                                     │                                   │ Webhooks     │
║                                     │ observaciones BBR                 └──────────────┘
║                                     ▼                                                   ║
║                          ┌──────────────────────┐                                       ║
║                          │    BBR Service       │                                       ║
║                          │    :8202             │                                       ║
║                          │                      │                                       ║
║                          │  • Registra duración │                                       ║
║                          │  • Tokens usados     │                                       ║
║                          │  • Calcula σ         │                                       ║
║                          │  • Detecta drift     │                                       ║
║                          └──────────────────────┘                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Flujo de creación de un agente (CAPA 1)

```
Developer                Creator API           AIM Service          AUT Service
    │                        │                      │                    │
    │  POST /v1/agents/create │                      │                    │
    │  {name, dept, tools...} │                      │                    │
    │────────────────────────►│                      │                    │
    │                        │                      │                    │
    │                        │  POST /register      │                    │
    │                        │  {name, dept, ...}   │                    │
    │                        │─────────────────────►│                    │
    │                        │                      │  Genera agent_id   │
    │                        │                      │  Crea credencial   │
    │                        │                      │  Computa HMAC      │
    │                        │  {credential 10 flds}│                    │
    │                        │◄─────────────────────│                    │
    │                        │                      │                    │
    │                        │  GET /autonomy/{id}  │                    │
    │                        │──────────────────────────────────────────►│
    │                        │                      │  Inicializa A0     │
    │                        │  {level: A0, σ: 1.5} │                    │
    │                        │◄──────────────────────────────────────────│
    │                        │                      │                    │
    │                        │  Genera bootstrap code SDK               │
    │                        │                      │                    │
    │  {agent_id,            │                      │                    │
    │   credential,          │                      │                    │
    │   bootstrap_code,      │                      │                    │
    │   gateway_url}         │                      │                    │
    │◄────────────────────────│                      │                    │
```

---

## Flujo de operación de una acción (CAPA 2)

```
Agente SDK               Gateway              OPA            Evidence Store      HIC
    │                       │                   │                   │              │
    │  @governed_tool       │                   │                   │              │
    │  decide(action, ...)  │                   │                   │              │
    │──────────────────────►│                   │                   │              │
    │                       │                   │                   │              │
    │                       │ ¿inyección?       │                   │              │
    │                       │ (local check)     │                   │              │
    │                       │                   │                   │              │
    │                       │  POST /v1/data/   │                   │              │
    │                       │  arhiax/main      │                   │              │
    │                       │  {input: {...}}   │                   │              │
    │                       │──────────────────►│                   │              │
    │                       │  {allow, reasons} │                   │              │
    │                       │◄──────────────────│                   │              │
    │                       │                   │                   │              │
    │                       │  POST /v1/evidence│                   │              │
    │                       │  {subject, action,│                   │              │
    │                       │   decision, ...}  │                   │              │
    │                       │──────────────────────────────────────►│              │
    │                       │  {id, hash}       │                   │              │
    │                       │◄──────────────────────────────────────│              │
    │                       │                   │                   │              │
    │  {allow, evidence_id} │                   │                   │              │
    │◄──────────────────────│                   │                   │              │
    │                       │                   │                   │              │
    │  Si ALLOW_WITH_HIC:   │                   │                   │              │
    │──────────────────────────────────────────────────────────────────────────────►
    │  POST /v1/tickets     │                   │                   │              │
    │  {agent_id, action,   │                   │                   │  Abre ticket │
    │   severity, ...}      │                   │                   │  Webhook →   │
    │◄──────────────────────────────────────────────────────────────────────────────
    │  {ticket_id, deadline}│                   │                   │              │
    │                       │                   │                   │              │
    │  Registra observación │                   │                   │              │
    │  en BBR (async)       │                   │                   │              │
```

---

## Modelo de datos: Credencial (10 campos)

```
Credential
├── agent_id                    "agent-a1b2c3d4e5f6"
├── name                        "AgenteDeAnalisis-v1"
├── supervisor_id               "supervisor-humano-001"
├── department_id               "dept-analytics"
├── authorization_boundary_id   "boundary-finanzas"
├── autonomy_level              "A0" → "A1" → ... → "A4"
├── credential_issued_at        "2026-04-19T12:00:00Z"
├── credential_expires_at       "2026-07-18T12:00:00Z"
├── rotation_policy             "90d"
├── lifecycle_state             "ACTIVE" | "ROTATING" | "SUSPENDED" | "RETIRED"
├── parent_chain_hmac           "sha256:abc123..." (cadena HMAC de identidad)
├── permitted_tools             ["consultar_db", "generar_reporte"]
├── permitted_data_scopes       ["analytics", "reportes"]
└── permitted_operations        ["modelInvoke", "toolCall", "dataAccess"]
```

---

## Modelo de datos: GovernanceDecision

```
GovernanceDecision
├── allow           bool
├── outcome         ALLOW | ALLOW_WITH_MONITORING | ALLOW_WITH_HIC_NOTIFICATION
│                   DENY | DENY_WITH_INCIDENT | ESCALATE_TO_HUMAN
├── reasons         ["POLICY_DENY", "INJECTION_DETECTED", ...]
├── obligations     [{"type": "rate_limit", "value": 100}]
├── evidence_id     "ev-0000001234"
└── hic_ticket_id   "hic-a1b2c3d4e5"  (si aplica)
```

---

## Modelo de datos: EvidenceRecord (ledger)

```
EvidenceRecord (en ledger JSONL)
├── id                  "ev-0000001234"
├── sequence_number     1234
├── timestamp           "2026-04-19T12:00:05Z"
├── subject             "agent-a1b2c3d4e5f6"
├── action              "toolCall"
├── resource            "consultar_base_datos"
├── context             {invocationId, operationType, ...}
├── decision            true | false
├── reasons             []
├── obligations         []
├── prev_hash           "sha256:prev..."    ← cadena Merkle
└── entry_hmac          "sha256:current..." ← HMAC de este registro
```

---

## Escala de autonomía y sus umbrales σ

La escala de autonomía determina cuánta desviación conductual puede tener un agente antes de ser escalado a supervisión humana.

```
Nivel  Nombre        σ threshold  Comportamiento
─────────────────────────────────────────────────────────────────
A0     Inerte        1.5σ         Todas las acciones requieren aprobación
A1     Supervisado   2.0σ         Alto impacto requiere aprobación
A2     Guiado        2.5σ         Impacto medio requiere aprobación
A3     Autónomo      3.0σ         Solo crítico requiere aprobación
A4     Adaptativo    3.5σ         Solo excepciones requieren aprobación

Si σ_observado > σ_umbral del nivel actual:
  → ESCALATE_TO_HUMAN (acción bloqueada)
  → AUT Service registra evento de degradación
  → Nivel puede bajar automáticamente si supera 3 veces en ventana
```

---

## Las 5 puertas de promoción de autonomía

Para subir de nivel (ej. A0 → A1), se evalúan 5 puertas simultáneamente. **Todas deben estar en verde**:

```
Puerta          Descripción
────────────────────────────────────────────────────────────────
G1_performance  Métricas de desempeño satisfactorias
                (precision, recall, tasa de éxito de tareas)

G2_security     Sin incidentes de seguridad en ventana de 30 días
                (0 inyecciones, 0 violaciones de política)

G3_business     Aprobación formal de la unidad de negocio
                (stakeholder sign-off documentado)

G4_history      Historial limpio de autonomía
                (no degradaciones en últimos 30 días)

G5_governance   Revisión del equipo de gobernanza aprobada
                (audit committee sign-off)
```

---

## Política OPA — lógica de evaluación

El Gateway consulta OPA para cada decisión. La política base sigue la lógica ARHIAX:

```
INPUT: {subject, action, resource, context}
        │
        ▼
  deny-by-default
  (allow := false si ninguna regla aplica)
        │
        ▼
  ¿inyección en payload?  → DENY (INJECTION_DETECTED)
        │
        ▼
  ¿tipo de operación válido?
  (toolCall, modelInvoke, dataAccess, interAgentCall)
        │
        ▼
  ¿nivel solicitado ≤ nivel certificado?
        │
        ▼
  ¿acción crítica con nivel A0-A3?  → DENY
        │
        ▼
  ¿acción de alto impacto?          → ALLOW + obligation: audit_log
        │
        ▼
  ALLOW + obligation: rate_limit
```

---

## Filosofía de diseño

| Principio | Implementación |
|-----------|----------------|
| **Gobernanza por diseño** | Los agentes nacen gobernados, no supervisados post-hoc |
| **Deny-by-default** | OPA niega todo salvo regla explícita de permiso |
| **Fail-closed en auth** | Si OPA o AIM no responden → DENY automático |
| **Fail-open en auditoría** | Si Evidence Store falla → decisión igual se retorna |
| **6 outcomes, no 2** | Gradación fina: evita bloqueos innecesarios y habilita monitoreo |
| **Evidencia primero** | Toda decisión produce registro inmutable antes de retornar |
| **Autonomía escalonada** | Sin saltos de nivel — solo promoción de A0→A1→A2→A3→A4 |
| **Circuit breaker** | GatewayClient abre circuito tras 5 fallos → evita cascadas |

---

## Dependencias y tecnologías

| Componente | Tecnología | Razón |
|-----------|-----------|-------|
| Todos los servicios | Python 3.12 + FastAPI + uvicorn | Rapidez de desarrollo, tipado con Pydantic |
| Almacenamiento | SQLite | Sin dependencias externas, fácil backup |
| Ledger de evidencia | JSONL + HMAC-SHA256 | Inmutable, verificable, sin DB |
| Políticas | OPA 0.68.0 + Rego | Estándar de facto en gobernanza de políticas |
| HTTP cliente SDK | httpx | Async nativo, retry, timeouts |
| Containerización | Docker + Compose | Despliegue reproducible |
| Métricas | Prometheus text format | Sin deps externas en gateway |

# ARHIAX AgentCreator

**Fábrica de agentes de IA gobernados bajo estándar ARHIAX**

ARHIAX AgentCreator es un sistema completo que permite crear, registrar y operar agentes de inteligencia artificial que nacen gobernados desde el primer instante. Cada agente creado con este sistema tiene identidad verificable, nivel de autonomía certificado, registro inmutable de cada acción y escalamiento automático a humanos cuando corresponde.

---

## Inicio rápido

```bash
# 1. Clonar y configurar
cp .env.example .env

# 2. Levantar el stack completo
docker compose up -d

# 3. Crear tu primer agente gobernado
curl -X POST http://localhost:8300/v1/agents/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MiPrimerAgente",
    "department_id": "dept-operaciones",
    "supervisor_id": "supervisor-humano-001",
    "permitted_tools": ["consultar_datos", "generar_reporte"],
    "permitted_operations": ["modelInvoke", "toolCall"]
  }'

# 4. Instalar el SDK en tu proyecto de agente
pip install -e sdk/python/

# 5. Ejecutar el ejemplo incluido
python sdk/python/examples/agente_analista.py
```

---

## Qué problema resuelve

Los agentes de IA tradicionales se construyen sin mecanismos de gobernanza integrados. Se les añade supervisión después, como parche. ARHIAX AgentCreator invierte ese orden: **el agente nace gobernado**.

Desde el momento en que el agente existe en el sistema:

- Tiene una **identidad criptográfica verificable** (AIM)
- Tiene un **nivel de autonomía certificado** (A0–A4)
- Cada acción que intenta ejecutar pasa por **evaluación de políticas** antes de ejecutarse
- Cada decisión queda en un **ledger inmutable con cadena HMAC-SHA256**
- Las acciones de alto impacto abren **tickets de aprobación humana** automáticamente
- La **desviación conductual** se detecta y escala si supera el umbral del nivel

---

## Arquitectura del sistema

```
                    ┌─────────────────────────────────┐
                    │      ARHIAX AgentCreator         │
                    │       Creator API :8300          │
                    │  "Fábrica de agentes gobernados" │
                    └────────────┬────────────────────┘
                                 │ orquesta
              ┌──────────────────┼──────────────────────┐
              │                  │                       │
              ▼                  ▼                       ▼
   ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
   │  AIM Service    │ │  AUT Service    │ │  HIC Service    │
   │  :8200          │ │  :8201          │ │  :8203          │
   │  Identidad y    │ │  Autonomía      │ │  Human-in-loop  │
   │  credenciales   │ │  A0 → A4        │ │  Tickets HIC    │
   └─────────────────┘ └─────────────────┘ └─────────────────┘

                    ┌─────────────────────────────────┐
                    │         ARHIAX SDK               │
                    │    pip install arhiax-sdk        │
                    │  ARHIAXAgent + @governed_tool    │
                    └────────────┬────────────────────┘
                                 │ llama a
                                 ▼
                    ┌─────────────────────────────────┐
                    │      Gateway (PEP) :8080         │
                    │  Policy Enforcement Point        │
                    │  Evalúa toda acción del agente   │
                    └──────┬──────────────┬───────────┘
                           │              │
                    ┌──────▼──────┐ ┌────▼──────────┐
                    │  OPA Engine │ │ Evidence Store │
                    │  :8181      │ │  :8090         │
                    │  19 bundles │ │  Ledger HMAC   │
                    │  Rego rules │ │  Merkle chain  │
                    └─────────────┘ └────────────────┘
                                          │
                    ┌─────────────────────▼───────────┐
                    │      BBR Service :8202           │
                    │  Behavioral Baseline Registry   │
                    │  Desviación sigma por agente    │
                    └─────────────────────────────────┘
```

---

## Servicios del stack

| Servicio | Puerto | Rol |
|---------|--------|-----|
| **creator-api** | 8300 | Fábrica — registra agentes, devuelve credencial + bootstrap code |
| **gateway** | 8080 | Policy Enforcement Point — evalúa cada acción con OPA |
| **aim-service** | 8200 | Agent Identity Management — credenciales, ciclo de vida |
| **aut-service** | 8201 | Autonomy Management — niveles A0–A4, promoción/degradación |
| **bbr-service** | 8202 | Behavioral Baseline Registry — desviación sigma |
| **hic-service** | 8203 | Human-in-the-Loop — tickets de aprobación con SLA |
| **evidence-store** | 8090 | Ledger inmutable JSONL + cadena HMAC-SHA256 |
| **opa** | 8181 | Motor de políticas OPA/Rego (19 bundles de políticas ARHIAX) |

---

## El SDK — cómo crea un agente gobernado

```python
from arhiax import ARHIAXAgent, governed_tool, ARHIAXDenied, ARHIAXEscalated

class AgenteDeAnalisis(ARHIAXAgent):
    """
    Este agente nace gobernado.
    Cada @governed_tool pasa por el Gateway de políticas ANTES de ejecutarse.
    """
    agent_id = "agent-abc123"        # Obtenido del Creator API
    gateway_url = "http://localhost:8080"

    @governed_tool(resource="consultar_base_datos", severity="MEDIUM")
    async def consultar_base_datos(self, query: str) -> dict:
        # ARHIAX evalúa esto automáticamente
        # Si el agente no tiene permiso → ARHIAXDenied
        # Si hay inyección → ARHIAXInjectionDetected
        # Si el impacto es alto → abre ticket HIC
        return await mi_db.execute(query)

    @governed_tool(resource="enviar_email", severity="HIGH")
    async def enviar_email(self, to: str, body: str) -> bool:
        # Alto impacto: ARHIAX notifica automáticamente al supervisor
        return await email_service.send(to, body)

    async def run(self, tarea: str) -> str:
        # invoke_model pasa por gobernanza ARHIAX
        return await self.invoke_model(prompt=tarea)


# Manejo de outcomes
async def main():
    async with AgenteDeAnalisis() as agente:
        try:
            resultado = await agente.consultar_base_datos("SELECT * FROM clientes")
            print(resultado)
        except ARHIAXDenied as e:
            print(f"Bloqueado: {e.reasons}")       # Política lo bloqueó
        except ARHIAXEscalated as e:
            print(f"Ticket: {e.ticket_id}")         # Esperando aprobación humana
```

---

## Niveles de autonomía A0–A4

Cada agente nace en **A0** y puede ser promovido a través de 5 puertas de evaluación:

| Nivel | Nombre | Comportamiento | Umbral σ |
|-------|--------|----------------|----------|
| **A0** | Inerte | Toda acción requiere aprobación humana | 1.5σ |
| **A1** | Supervisado | Acciones de alto impacto requieren aprobación | 2.0σ |
| **A2** | Guiado | Impacto medio requiere aprobación | 2.5σ |
| **A3** | Autónomo | Solo acciones críticas requieren aprobación | 3.0σ |
| **A4** | Adaptativo | Solo excepciones requieren aprobación | 3.5σ |

Para promover un agente de A0 a A1, las 5 puertas deben estar en verde:

```bash
curl -X POST http://localhost:8300/v1/agents/{agent_id}/promote \
  -H "Content-Type: application/json" \
  -d '{
    "target_level": "A1",
    "gates": {
      "G1_performance": true,
      "G2_security": true,
      "G3_business": true,
      "G4_history": true,
      "G5_governance": true
    },
    "justification": "30 días de operación sin incidentes"
  }'
```

---

## Los 6 outcomes de gobernanza

Cada acción evaluada por el Gateway termina en uno de 6 outcomes:

| Outcome | Qué significa | Qué pasa |
|---------|--------------|----------|
| `ALLOW` | Todo correcto | Acción ejecutada |
| `ALLOW_WITH_MONITORING` | BBR sin datos base | Ejecuta + métricas extras |
| `ALLOW_WITH_HIC_NOTIFICATION` | Alto impacto, checks ok | Ejecuta + notifica supervisor |
| `DENY` | Política o autonomía violated | Lanza `ARHIAXDenied` |
| `DENY_WITH_INCIDENT` | Inyección detectada | Lanza `ARHIAXInjectionDetected` + incidente |
| `ESCALATE_TO_HUMAN` | Desviación σ excedida | Lanza `ARHIAXEscalated` + ticket HIC |

---

## Evidencia inmutable

Cada decisión queda registrada con cadena HMAC-SHA256:

```bash
# Ver todas las decisiones registradas
curl http://localhost:8090/v1/evidence

# Verificar integridad de toda la cadena
curl http://localhost:8090/v1/evidence/verify/chain

# Ver cabeza actual
curl http://localhost:8090/v1/head
```

---

## Estructura de archivos

```
ARHIAX-AgentCreator/
├── README.md                    ← Este archivo
├── ARCHITECTURE.md              ← Arquitectura detallada
├── API_REFERENCE.md             ← Referencia completa de APIs
├── DEPLOYMENT.md                ← Guía de despliegue
├── SECURITY.md                  ← Política de seguridad
├── CHANGELOG.md                 ← Historial de cambios
├── CONTRIBUTING.md              ← Cómo contribuir
│
├── docker-compose.yml
├── .env.example
│
├── services/
│   ├── creator-api/             ← Fábrica de agentes
│   ├── gateway/                 ← Policy Enforcement Point
│   ├── aim-service/             ← Identidad de agentes
│   ├── aut-service/             ← Autonomía A0-A4
│   ├── bbr-service/             ← Baseline conductual
│   ├── hic-service/             ← Human-in-the-loop
│   └── evidence-store/          ← Ledger inmutable
│
├── sdk/python/
│   ├── arhiax/                  ← Paquete SDK
│   ├── examples/                ← Agentes de ejemplo
│   └── setup.py
│
└── runtime/
    └── bundles/                 ← 19 bundles de políticas OPA
```

---

## Requisitos

- Docker Desktop 4.x o superior
- Docker Compose v2
- Python 3.10+ (para el SDK)
- 2 GB RAM mínimo para el stack completo

---

## Licencia

ARHIAX AgentCreator — Sinergia Consulting Group  
Sistema de gobernanza de agentes IA bajo estándar ARHIAX

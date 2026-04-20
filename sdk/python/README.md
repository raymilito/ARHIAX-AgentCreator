# ARHIAX SDK — Python

**Librería para crear agentes de IA gobernados bajo estándar ARHIAX**

---

## Instalación

```bash
# Desde el directorio del proyecto
pip install -e sdk/python/

# Con soporte para Claude (Anthropic)
pip install -e "sdk/python/[anthropic]"
```

---

## Concepto central

El SDK convierte cualquier clase Python en un agente gobernado con una sola línea de herencia:

```python
from arhiax import ARHIAXAgent, governed_tool

class MiAgente(ARHIAXAgent):
    agent_id = "agent-abc123"      # Obtenido del Creator API
    gateway_url = "http://localhost:8080"
```

A partir de ese momento, **cualquier método decorado con `@governed_tool` pasa automáticamente por el Gateway de políticas ARHIAX antes de ejecutarse**. El agente no puede saltarse este mecanismo.

---

## Guía rápida

### 1. Crear el agente en ARHIAX Creator API

```bash
curl -X POST http://localhost:8300/v1/agents/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MiAgente",
    "department_id": "dept-ops",
    "supervisor_id": "supervisor-001",
    "permitted_tools": ["buscar", "guardar", "notificar"]
  }'
```

Guarda el `agent_id` del response.

### 2. Definir tu agente con el SDK

```python
from arhiax import ARHIAXAgent, governed_tool
from arhiax import ARHIAXDenied, ARHIAXEscalated, ARHIAXInjectionDetected

class MiAgente(ARHIAXAgent):
    agent_id = "agent-abc123"          # Del Creator API
    gateway_url = "http://localhost:8080"
    aim_url = "http://localhost:8200"
    hic_url = "http://localhost:8203"
    bbr_url = "http://localhost:8202"

    @governed_tool(
        action="toolCall",
        resource="buscar",
        severity="LOW",
        autonomy_level="A1",
    )
    async def buscar(self, query: str) -> list:
        # ARHIAX evalúa esta llamada ANTES de ejecutar.
        # Si el agente no tiene permiso → ARHIAXDenied
        # Si hay inyección → ARHIAXInjectionDetected
        return await mi_api_de_busqueda.search(query)

    @governed_tool(
        action="toolCall",
        resource="notificar",
        severity="HIGH",       # Alto impacto → abre ticket HIC
        autonomy_level="A2",
    )
    async def notificar(self, destinatario: str, mensaje: str) -> bool:
        return await servicio_email.send(destinatario, mensaje)

    async def _call_llm(self, prompt: str, model: str, system_prompt: str = "") -> str:
        # Implementa aquí tu llamada al LLM
        import anthropic
        client = anthropic.Anthropic()
        msg = client.messages.create(
            model=model, max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        return msg.content[0].text

    async def run(self, tarea: str) -> str:
        # invoke_model también pasa por gobernanza
        return await self.invoke_model(prompt=tarea)
```

### 3. Ejecutar con manejo de outcomes

```python
import asyncio

async def main():
    async with MiAgente() as agente:
        try:
            # Acción normal
            resultados = await agente.buscar("ventas Q1 2026")
            print(f"Encontrado: {resultados}")

            # Invocar modelo (también gobernado)
            analisis = await agente.invoke_model(
                prompt=f"Analiza estos datos: {resultados}",
                system_prompt="Eres un analista financiero experto."
            )
            print(f"Análisis: {analisis}")

            # Acción de alto impacto (puede generar ticket HIC)
            await agente.notificar("cfo@empresa.com", f"Análisis listo: {analisis[:200]}")

        except ARHIAXDenied as e:
            # El Gateway bloqueó la acción por política
            print(f"Bloqueado: {e.reasons}")
            print(f"Evidencia: {e.evidence_id}")

        except ARHIAXEscalated as e:
            # Desviación sigma excedida — esperando aprobación humana
            print(f"Escalado a humano. Ticket: {e.ticket_id}")

        except ARHIAXInjectionDetected as e:
            # Patrón de inyección en el input
            print(f"Inyección bloqueada. Incidente: {e.evidence_id}")

asyncio.run(main())
```

---

## El decorador `@governed_tool`

```python
@governed_tool(
    action="toolCall",        # Tipo de acción (toolCall, dataAccess, etc.)
    resource="nombre_tool",   # Nombre del recurso (default: nombre del método)
    severity="MEDIUM",        # LOW | MEDIUM | HIGH | CRITICAL
    autonomy_level="A1",      # Nivel mínimo requerido para esta acción
)
async def mi_herramienta(self, param: str) -> Any:
    ...
```

**Qué hace el decorador automáticamente:**

1. Verifica que la herramienta está en `permitted_tools` de la credencial
2. Llama al Gateway → `POST /v1/decide`
3. Maneja el outcome:
   - `ALLOW` → ejecuta el método
   - `DENY` → lanza `ARHIAXDenied`
   - `DENY_WITH_INCIDENT` → lanza `ARHIAXInjectionDetected`
   - `ESCALATE_TO_HUMAN` → lanza `ARHIAXEscalated`
   - `ALLOW_WITH_HIC_NOTIFICATION` → ejecuta + abre ticket HIC
4. Registra la observación en BBR (duración, tokens, outcome)

---

## `invoke_model` — LLM gobernado

```python
response = await agente.invoke_model(
    prompt="¿Cuáles son las tendencias de ventas?",
    model="claude-sonnet-4-6",
    system_prompt="Eres un analista senior.",
    requested_autonomy_level="A1",
)
```

Sobreescribe `_call_llm` para conectar con tu proveedor de LLM.

---

## `access_data` — Acceso a datos gobernado

```python
decision = await agente.access_data(
    scope="analytics",
    resource="db-ventas",
    operation="read",
)
# Si allow=True, procede con el acceso
```

---

## `call_agent` — Llamadas inter-agente gobernadas

```python
decision = await agente.call_agent(
    target_agent_id="agent-xyz789",
    message={"tarea": "procesar_factura", "id": "F-001"},
    context_chain=["agent-abc123"],  # Cadena de delegación
)
```

---

## Configuración por variables de entorno

Si no quieres hardcodear las URLs en la clase:

```bash
export ARHIAX_GATEWAY_URL=http://localhost:8080
export ARHIAX_AIM_URL=http://localhost:8200
export ARHIAX_HIC_URL=http://localhost:8203
export ARHIAX_BBR_URL=http://localhost:8202
```

---

## Excepciones del SDK

| Excepción | Cuándo | Atributos clave |
|-----------|--------|-----------------|
| `ARHIAXDenied` | Gateway bloqueó la acción | `.reasons`, `.evidence_id` |
| `ARHIAXEscalated` | Requiere aprobación humana | `.ticket_id` |
| `ARHIAXInjectionDetected` | Inyección en input | `.evidence_id` |
| `ARHIAXCredentialExpired` | Credencial no ACTIVE | `.lifecycle_state` |
| `ARHIAXToolNotPermitted` | Tool no en `permitted_tools` | `.tool_name`, `.permitted` |
| `ARHIAXServiceUnavailable` | Gateway u otro servicio caído | `.service` |

---

## Context manager

```python
# Forma recomendada — carga credencial automáticamente al entrar
async with MiAgente() as agente:
    resultado = await agente.run("mi tarea")

# Alternativa — pasar credencial directamente
agente = MiAgente(credential={...})  # dict del Creator API
resultado = await agente.run("mi tarea")
```

---

## Ejemplo completo

Ver [`examples/agente_analista.py`](examples/agente_analista.py) para un agente completo con múltiples herramientas, manejo de todos los outcomes y demostración de detección de inyección.

# Guía de Contribución — ARHIAX AgentCreator

---

## Cómo contribuir

### 1. Entender la arquitectura primero

Lee `ARCHITECTURE.md` completo antes de hacer cambios. El sistema tiene capas bien definidas y cada cambio debe respetar el principio de **gobernanza por diseño**: los agentes nacen gobernados, no se les añade gobernanza después.

---

## Estructura de servicios

Cada servicio sigue el mismo patrón:

```
services/{nombre-servicio}/
├── main.py          ← FastAPI app, modelos, endpoints, lógica
├── requirements.txt ← Dependencias Python
├── Dockerfile       ← Imagen Docker
└── README.md        ← Documentación del servicio
```

Mantén **toda la lógica en `main.py`**. No fragmentes en múltiples archivos a menos que el servicio supere las 500 líneas.

---

## Agregar un nuevo endpoint a un servicio

1. Define el modelo Pydantic de request/response
2. Implementa el endpoint con FastAPI
3. Documenta en el `README.md` del servicio
4. Agrega la referencia en `API_REFERENCE.md`

---

## Modificar políticas OPA

Las políticas están en `runtime/bundles/`. La política base del Gateway está en `runtime/bundles/main.rego`.

Reglas al modificar políticas:
- **Nunca quitar deny-by-default**
- Toda nueva regla de permiso debe tener su negativa explícita en `reasons`
- Probar la política con `opa eval` antes de deploy
- Documentar el cambio en `CHANGELOG.md`

```bash
# Probar una política OPA
opa eval --data runtime/bundles/main.rego --input test_input.json "data.arhiax.main.allow"
```

---

## Modificar el SDK

El SDK está en `sdk/python/arhiax/`. Los cambios que afecten la interfaz pública (`ARHIAXAgent`, `governed_tool`) deben ser retrocompatibles.

```bash
# Instalar en modo editable para desarrollo
pip install -e "sdk/python/[dev]"

# Ejecutar el ejemplo para verificar
python sdk/python/examples/agente_analista.py
```

---

## Principios de diseño a respetar

| Principio | Cómo aplicarlo |
|-----------|---------------|
| **Fail-closed en auth** | Si un servicio crítico (OPA, AIM) no responde → DENY, nunca ALLOW |
| **Fail-open en auditoría** | Si Evidence Store no responde → retornar decisión, no bloquear |
| **Sin magia implícita** | El SDK debe ser explícito: si algo pasa por gobernanza, debe ser obvio en el código |
| **Un solo archivo por servicio** | Mantener `main.py` cohesivo, no fragmentar prematuramente |
| **SQLite para persistencia** | Sin dependencias de DB externas — facilita despliegue y backup |

---

## Convenciones de código

```python
# ✓ Correcto: modelos Pydantic con nombres claros
class AgentRegistration(BaseModel):
    name: str
    department_id: str

# ✗ Evitar: dicts sin tipado
def register(data: dict) -> dict:
    ...

# ✓ Correcto: endpoints async
@app.post("/v1/agents/register")
async def register_agent(reg: AgentRegistration):
    ...

# ✓ Correcto: manejo explícito de errores
if not row:
    raise HTTPException(404, f"Agente {agent_id} no encontrado")

# ✓ Correcto: comentarios solo cuando el WHY no es obvio
# HMAC usa prev_hash para hacer que cualquier modificación invalide
# todos los registros posteriores — eso es el punto de la cadena
entry_hmac = _compute_hmac(_last_hash, entry_json)
```

---

## Checklist antes de hacer cambios

- [ ] ¿El cambio respeta deny-by-default?
- [ ] ¿Los servicios críticos siguen siendo fail-closed?
- [ ] ¿El Evidence Store sigue siendo append-only?
- [ ] ¿El agente no puede saltarse el Gateway?
- [ ] ¿Hay un README actualizado?
- [ ] ¿Está documentado en `API_REFERENCE.md` si es un endpoint nuevo?
- [ ] ¿Está en `CHANGELOG.md`?

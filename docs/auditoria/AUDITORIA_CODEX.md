# Auditoria Tecnica del Repositorio (Codex)

**Autoria:** Este documento fue elaborado por **Codex (GPT-5)** en esta conversacion.  
**Marca de propiedad:** `AUDITORIA_CODEX`  
**Fecha:** 2026-04-10  
**Objetivo:** Diferenciar esta auditoria de otras auditorias hechas por otras IAs.

## Alcance revisado
- Raiz del paquete (`arhia_atk_service.py`, `mcp_interceptor.py`, `demo.py`, `test_integration.py`, `authz*.rego`, `Dockerfile`).
- `ARHIAX 11.4/files 11` (ATK v11.4 + tests + interceptor).
- `ARHIAX 11.4/files 13` (hardened clients + selector de modo + CI).
- `ARHIAX 11.4/arhiax-images-1.0.0` (gateway, evidence-store, correlator).
- `ARHIAX 11.4/arhiax-runtime` (Helm chart + policies + validador).

## Resumen ejecutivo
- Hallazgos criticos: **3**
- Hallazgos altos: **2**
- Hallazgos medios: **7**
- Hallazgos bajos: **1**

## Veredicto
**NO APTO PARA PRODUCCION en el estado actual.**

Condicion minima para cambiar a "Apto con reservas":
- Cerrar **C1, C2, C3, A1 y A2**.

Condicion para "Apto para produccion":
- Cerrar lo anterior y mitigar los hallazgos **M1-M7** segun riesgo operativo.

## Hallazgos (priorizados)

### [C1] CRITICO - `client_mode` no arranca en development
- Archivo: `ARHIAX 11.4/files 13/client_mode.py`
- Problema:
  - Importa `arhiax_atk_service` fuera de su arbol.
  - Llama `InMemoryAIM()` sin `credentials` requeridos.
- Impacto: rompe el arranque del modo development.

### [C2] CRITICO - Validacion MCP incompleta
- Archivo: `mcp_interceptor.py` (raiz)
- Problema: se extraen `scope/token_zone/token_ceiling/token_cap`, pero no se validan contra `tool/params`.
- Impacto: riesgo de autorizacion indebida.

### [C3] CRITICO - Gateway productivo sin enforcement de auth/rate-limit
- Archivo: `ARHIAX 11.4/arhiax-images-1.0.0/gateway/internal/server/server.go`
- Problema: endpoint `/v1/decide` acepta input directo y decide sin validar JWT en capa HTTP.
- Impacto: exposicion de control-plane si el endpoint queda accesible.

### [A1] ALTO - Docker build roto por archivo faltante
- Archivo: `Dockerfile` (raiz)
- Problema: `COPY aibom.json ./` pero no existe `aibom.json`.
- Impacto: falla de build.

### [A2] ALTO - Suite principal incompleta por falta de AIBOM
- Archivo: `test_integration.py` (raiz)
- Problema: test espera `demo-local-slm-v1` en cache AIBOM, pero no hay fuente `aibom*.json`.
- Impacto: 1 test funcional falla (21/22).

### [M1] MEDIO - Validador Helm con falsos negativos en Windows
- Archivo: `ARHIAX 11.4/arhiax-runtime/scripts/validate_chart.py`
- Problema: mezcla separadores `\` y `/` para llaves de rutas.
- Impacto: reporte erroneo de multiples fallas en subchart correlator.

### [M2] MEDIO - Test principal no portable por encoding de consola
- Archivo: `test_integration.py` (raiz)
- Problema: imprime caracteres Unicode que rompen en cp1252 sin `PYTHONIOENCODING=utf-8`.
- Impacto: ejecucion falla en Windows por entorno.

### [M3] MEDIO - Inconsistencia Python 3.12/3.11 en imagen correlator
- Archivo: `ARHIAX 11.4/arhiax-images-1.0.0/correlator/Dockerfile`
- Problema: build stage 3.12, runtime distroless python 3.11, `PYTHONPATH` fijo 3.11.
- Impacto: alta probabilidad de ruptura al agregar dependencias reales.

### [M4] MEDIO - Defaults de URL en correlator subchart fragiles
- Archivo: `ARHIAX 11.4/arhiax-runtime/charts/correlator/templates/deployment.yaml`
- Problema: URLs por defecto hardcodeadas al patron de nombre esperado.
- Impacto: fallas con `fullnameOverride/nameOverride`.

### [M5] MEDIO - OPA subprocess no portable a Windows
- Archivo: `arhia_atk_service.py` (raiz)
- Problema: usa `--input /dev/stdin` en invocacion OPA.
- Impacto: ruta no valida en Windows.

### [M6] MEDIO - Token de aprobacion humana con `sub` inconsistente
- Archivo: `arhia_atk_service.py` (raiz)
- Problema: token de workbench usa `sub=trace_id` en vez de actor.
- Impacto: trazabilidad/identidad confusa.

### [M7] MEDIO - CI no alineado con estructura real del paquete
- Archivo: `ARHIAX 11.4/files 13/arhiax-ci.yml`
- Problema: referencia rutas y contexto (`runtime/`, `chart/`) no presentes en este paquete.
- Impacto: pipeline no reproducible en este snapshot.

### [B1] BAJO - Defaults de seguridad endurecibles en chart
- Archivo: `ARHIAX 11.4/arhiax-runtime/values.yaml`
- Problema:
  - `networkPolicy.enabled=false`
  - `gateway.serviceAccount.automountServiceAccountToken=true`
- Impacto: postura por defecto menos restrictiva.

## Evidencia de ejecucion (resumen)
- `python -m pytest -q -p no:cacheprovider ARHIAX 11.4/files 11/test_integration.py` -> **21 passed**.
- `PYTHONIOENCODING=utf-8 python test_integration.py` (raiz) -> **21/22**, falla AIBOM faltante.
- `python ARHIAX 11.4/arhiax-runtime/scripts/validate_chart.py` -> falla por issue del validador (paths).
- `go test ./...` en gateway y evidence-store -> compila paquetes, error final de permisos al limpiar cache Go.
- `python -m pytest ... files 13/test_hardened_clients.py` -> no ejecuta por dependencia faltante `respx`.

## Nota de identificacion
Si estas consolidando varias auditorias IA, usa esta marca para esta version:

`SOURCE=AUDITORIA_CODEX | AUTHOR=Codex(GPT-5) | DATE=2026-04-10`

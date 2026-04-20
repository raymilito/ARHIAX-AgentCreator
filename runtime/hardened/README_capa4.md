# ARHIAX v11.4 — Capa 4: Hardened Clients + Pilots + CI/CD

Paquete de integración que completa el runtime ARHIAX v11.4 para despliegue en
producción. Se enchufa encima de las Capas 1-3b ya entregadas sin romper nada.

---

## Contenido (11 archivos)

### A. Hardened Production Clients (4 archivos)

Reemplazo de los `InMemory*` del ATK service cuando `ARHIAX_MODE=production`.

| Archivo | Rol | LoC |
|---|---|---|
| `hardened_base.py` | Base class con httpx async + tenacity retry + circuit breaker + Prometheus | ~425 |
| `hardened_clients.py` | 6 clientes concretos: AIM, OPA, AUT, BBR, EGA, HIC | ~330 |
| `client_mode.py` | Selector `development` / `production` / `shadow` | ~115 |
| `test_hardened_clients.py` | **28/28 pytest verdes** | ~475 |

### B. Merge de bundles (1 archivo)

| Archivo | Rol |
|---|---|
| `merge_bundles.py` | Consolida `authz.rego` + `bundles_b01_b19.rego` → `arhiax_all_bundles.rego` |

### C. Values files por pilot (3 archivos)

| Archivo | Pilot | Perfil clave |
|---|---|---|
| `values-sprbun.yaml` | PORT-MAS @ SPRBUN | Air-gapped, B12 primary, 13 bundles, HPA 3-12 |
| `values-brasil-fintech.yaml` | ARHIAX Brasil PSAV | ZDE mode, B13 STRICT, br-only, HPA 5-50 |
| `values-arhia-hfl.yaml` | ARHIA HFL shadow | Shadow pilot, sub-20ms p99, B06+B12 observe |

### D. CI/CD (2 archivos)

| Archivo | Frecuencia | Jobs |
|---|---|---|
| `arhiax-ci.yml` | Push + PR + tag | lint → test → build → scan → helm → smoke → release |
| `arhiax-nightly-audit.yml` | Nightly 06:00 UTC | pip-audit, trivy-fs, kubesec, opa-coverage |

### E. Este README (1 archivo)

---

## Integración al paquete existente

### Estructura de directorios sugerida

```
arhiax-v114/
├── docs/                                  # Capa 1 — 7 docs maestros
│   ├── ARHIAX_v114_Master_Architecture_EN.docx
│   ├── ARHIAX_v114_Whitepaper_EN.docx
│   ├── ARHIAX_v114_36_Controles_Gobernanza_MultiAgente.docx
│   ├── ARHIAX_v114_Hoja_de_Ruta_Ruta_C.docx
│   ├── ARHIAX_v114_Annex_Compendium_EN.docx
│   ├── ARHIAX_v114_ATK_Reference_Implementation_Profile.docx
│   └── ARHIAX_v114_Remediation_Traceability_Matrix.docx
│
├── runtime/                               # Capas 2 + 3 + 4 (código)
│   ├── arhiax_atk_service.py              # Capa 2
│   ├── mcp_interceptor.py                 # Capa 2
│   ├── demo.py                            # Capa 2
│   ├── authz.rego                         # Capa 2 (B14 + B16)
│   ├── authz_test.rego                    # Capa 2
│   ├── bundles_b01_b19.rego               # Capa 3
│   ├── bundles_b01_b19_test.rego          # Capa 3
│   ├── opa_bundles.py                     # Capa 3 (mirror Python)
│   ├── test_integration.py                # Capa 2 (21 tests)
│   ├── test_bundles_b01_b19.py            # Capa 3 (95 tests)
│   │
│   ├── hardened_base.py                   # ← Capa 4 (NEW)
│   ├── hardened_clients.py                # ← Capa 4 (NEW)
│   ├── client_mode.py                     # ← Capa 4 (NEW)
│   ├── test_hardened_clients.py           # ← Capa 4 (NEW, 28 tests)
│   ├── merge_bundles.py                   # ← Capa 4 (NEW)
│   │
│   ├── Dockerfile                         # Capa 2/3 (actualizar — ver abajo)
│   ├── requirements.txt                   # actualizar — ver abajo
│   └── README.md                          # Capa 2
│
├── chart/
│   └── arhiax-runtime/                    # Capa 3b (Helm chart)
│       ├── Chart.yaml
│       ├── values.yaml                    # defaults
│       ├── values-sprbun.yaml             # ← Capa 4 (NEW)
│       ├── values-brasil-fintech.yaml     # ← Capa 4 (NEW)
│       ├── values-arhia-hfl.yaml          # ← Capa 4 (NEW)
│       ├── templates/
│       ├── dashboards/
│       └── files/
│
└── .github/
    └── workflows/
        ├── arhiax-ci.yml                  # ← Capa 4 (NEW)
        └── arhiax-nightly-audit.yml       # ← Capa 4 (NEW)
```

---

## Cambios requeridos en archivos existentes

### 1. `runtime/requirements.txt` — añadir dependencias

Añadir al final del archivo (las 3 primeras son runtime, las 3 últimas dev):

```
httpx>=0.27.0
tenacity>=8.2.0
prometheus-client>=0.20.0

# dev / test
pytest-asyncio>=0.23.0
respx>=0.21.0
```

### 2. `runtime/arhiax_atk_service.py` — factory mode-aware

Reemplazar el bloque que construye los clientes InMemory por el factory de
`client_mode.py`. El patch es aditivo: si `ARHIAX_MODE` no está definido,
se comporta exactamente igual que antes (development con InMemory).

```python
# AL INICIO DEL MÓDULO (después de los imports existentes):
from client_mode import build_clients, attest_clients, close_clients


# EN EL FACTORY _build_default_app() — reemplazar la construcción manual
# de InMemoryAIM()/InMemoryOPA()/etc. por:
def _build_default_app():
    clients = build_clients()
    atk = ATKService(
        aim=clients["aim"],
        opa=clients["opa"],
        aut=clients["aut"],
        bbr=clients["bbr"],
        ega=clients["ega"],
        hic=clients["hic"],
    )
    # ATK-C07 startup attestation
    import asyncio
    attestation = asyncio.get_event_loop().run_until_complete(
        attest_clients(clients)
    )
    atk.record_startup_attestation(attestation)
    return atk.asgi_app()
```

**Impacto en los 21 tests de `test_integration.py`:** ninguno. Los tests
instancian `ATKService` directamente con `InMemory*`, no pasan por el factory.

### 3. `runtime/Dockerfile` — ya incluye httpx/tenacity/prometheus

Si tu Dockerfile actual hace `pip install -r requirements.txt` (como el de
Capa 2), el update de requirements.txt es suficiente. El `HEALTHCHECK` sigue
funcionando porque no depende del modo.

**Opcional pero recomendado:** añadir un env var default al Dockerfile para
que builds sin override arranquen en development:

```dockerfile
ENV ARHIAX_MODE=development
```

### 4. `chart/arhiax-runtime/templates/deployment.yaml` — env vars para clientes

Si aún no tienes el bloque de env vars para los hardened clients en tu
deployment.yaml, agrégalo dentro del contenedor ATK (los values files ya
los configuran via `arhiax.clients.*` pero el template tiene que leerlos):

```yaml
- name: ARHIAX_MODE
  value: {{ .Values.arhiax.mode | default "development" | quote }}
{{- if eq (.Values.arhiax.mode | default "development") "production" }}
- name: ARHIAX_AIM_URL
  value: {{ .Values.arhiax.clients.aim.url | quote }}
- name: ARHIAX_AIM_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.arhiax.clients.aim.tokenSecretRef.name }}
      key: {{ .Values.arhiax.clients.aim.tokenSecretRef.key }}
- name: ARHIAX_AIM_TIMEOUT
  value: {{ .Values.arhiax.clients.aim.timeoutSeconds | default 5 | quote }}
# ... repetir para opa, aut, bbr, ega, hic
{{- end }}
```

---

## Variables de entorno — contrato completo

Cuando `ARHIAX_MODE=production`, el ATK espera estas 6 familias de variables
(una por cliente). Prefijos y defaults:

| Prefijo | Obligatorias | Opcionales (con defaults) |
|---|---|---|
| `ARHIAX_AIM_` | `URL` | `TOKEN`, `TIMEOUT=5`, `CONNECT_TIMEOUT=2`, `MAX_RETRIES=3`, `RETRY_MIN_WAIT=0.1`, `RETRY_MAX_WAIT=2.0`, `CIRCUIT_THRESHOLD=5`, `CIRCUIT_RESET=30`, `POOL_MAX=20`, `POOL_KEEPALIVE=10`, `VERIFY_TLS=true` |
| `ARHIAX_OPA_` | `URL` | (mismos defaults) |
| `ARHIAX_AUT_` | `URL` | (mismos defaults) |
| `ARHIAX_BBR_` | `URL` | (mismos defaults) |
| `ARHIAX_EGA_` | `URL` | (mismos defaults) |
| `ARHIAX_HIC_` | `URL` | (mismos defaults) |

Además:

| Variable | Valores | Default |
|---|---|---|
| `ARHIAX_MODE` | `development` / `production` / `shadow` | `development` |
| `ARHIAX_VERSION` | string libre (se usa en User-Agent) | `11.4` |

**Importante:** el fail-fast al arrancar es intencional. Si falta cualquier
`_URL` obligatoria en modo production, el ATK no levanta y emite un
`ValueError` claro en el log. Es preferible a descubrir la falta de config
a mitad de un pico de tráfico en producción.

---

## Smoke test local (sin CI)

Sin kind, sin Docker — solo Python:

```bash
cd runtime/

# 1. Instalar dependencias actualizadas
pip install -r requirements.txt

# 2. Correr las 4 suites de tests (esperado: 144 tests verdes)
pytest test_integration.py test_bundles_b01_b19.py test_hardened_clients.py -v

# 3. Verificar el merge de bundles (produce arhiax_all_bundles.rego)
python merge_bundles.py authz.rego bundles_b01_b19.rego arhiax_all_bundles.rego

# 4. Verificar que el modo se selecciona correctamente
ARHIAX_MODE=development python -c "from client_mode import build_clients; \
  clients = build_clients(); \
  print(list(clients.keys())); \
  print(type(clients['aim']).__name__)"
# Esperado: ['aim', 'opa', 'aut', 'bbr', 'ega', 'hic']
#           InMemoryAIM

# 5. (Opcional) Verificar modo production — requiere env vars
ARHIAX_MODE=production \
  ARHIAX_AIM_URL=https://aim.example.com \
  ARHIAX_OPA_URL=http://localhost:8181 \
  ARHIAX_AUT_URL=https://aut.example.com \
  ARHIAX_BBR_URL=https://bbr.example.com \
  ARHIAX_EGA_URL=https://ega.example.com \
  ARHIAX_HIC_URL=https://hic.example.com \
  python -c "from client_mode import build_clients; \
    clients = build_clients(); \
    print(type(clients['aim']).__name__)"
# Esperado: HardenedAIMClient
```

---

## Métricas Prometheus expuestas

Los hardened clients exponen 4 métricas en `/metrics` (además de las del ATK):

| Métrica | Tipo | Labels |
|---|---|---|
| `arhiax_client_requests_total` | Counter | `client`, `method`, `endpoint`, `outcome` |
| `arhiax_client_latency_seconds` | Histogram | `client`, `method`, `endpoint` |
| `arhiax_client_circuit_state` | Gauge | `client` (0=closed, 1=half_open, 2=open) |
| `arhiax_client_retry_total` | Counter | `client`, `endpoint` |

**Alertas recomendadas (PromQL):**

```promql
# Circuit breaker abierto por más de 1 minuto
ALERT ARHIAXClientCircuitOpen
  IF arhiax_client_circuit_state == 2
  FOR 1m
  LABELS { severity = "critical" }

# Tasa de errores upstream > 5% en ventana de 5min
ALERT ARHIAXClientErrorRate
  IF sum(rate(arhiax_client_requests_total{outcome!="success"}[5m])) by (client)
   / sum(rate(arhiax_client_requests_total[5m])) by (client)
   > 0.05
  FOR 5m

# Latencia p99 > 500ms sostenida
ALERT ARHIAXClientLatencyP99
  IF histogram_quantile(0.99, rate(arhiax_client_latency_seconds_bucket[5m])) > 0.5
  FOR 10m
```

---

## Deploy por pilot — comandos

```bash
# SPRBUN (port logistics, air-gapped)
helm install arhiax-sprbun chart/arhiax-runtime \
  -f chart/arhiax-runtime/values.yaml \
  -f chart/arhiax-runtime/values-sprbun.yaml \
  --namespace arhiax-sprbun \
  --create-namespace

# ARHIAX Brasil (fintech PSAV, ZDE mode)
helm install arhiax-br chart/arhiax-runtime \
  -f chart/arhiax-runtime/values.yaml \
  -f chart/arhiax-runtime/values-brasil-fintech.yaml \
  --namespace arhiax-brasil \
  --create-namespace

# ARHIA HFL (shadow pilot)
helm install arhiax-hfl chart/arhiax-runtime \
  -f chart/arhiax-runtime/values.yaml \
  -f chart/arhiax-runtime/values-arhia-hfl.yaml \
  --namespace arhiax-hfl \
  --create-namespace
```

Antes del primer deploy, crea los secrets por pilot:

```bash
kubectl create secret generic arhiax-sprbun-secrets \
  --from-literal=aim-token="$SPRBUN_AIM_TOKEN" \
  --from-literal=aut-token="$SPRBUN_AUT_TOKEN" \
  --from-literal=ega-token="$SPRBUN_EGA_TOKEN" \
  --from-literal=hic-token="$SPRBUN_HIC_TOKEN" \
  -n arhiax-sprbun
```

---

## CI/CD — configuración inicial

### GitHub repo secrets requeridos

| Secret | Uso |
|---|---|
| `GITHUB_TOKEN` | auto-provisto, usado para GHCR push y Helm OCI |

### Branch protection recomendada (main)

- Require PR with at least 1 approval
- Require status checks: `lint`, `test`, `build`, `helm`
- Require linear history
- No force push

### Tagging para release

```bash
git tag -a v11.4.0 -m "ARHIAX v11.4.0 — initial production release"
git push origin v11.4.0
```

Esto dispara el workflow completo incluyendo `release` job, que crea un
GitHub Release con la imagen `ghcr.io/sinergia/arhiax-atk:11.4.0` y el
chart OCI `oci://ghcr.io/sinergia/charts/arhiax-runtime:0.1.0`.

---

## Matriz de validación

| Componente | Validado en sandbox | Cómo validar localmente |
|---|---|---|
| Hardened clients | ✅ 28/28 pytest (respx mocks) | `pytest test_hardened_clients.py -v` |
| Merge bundles | ✅ Script probado con 19 packages stub | `python merge_bundles.py ...` |
| Values YAML sintaxis | ✅ PyYAML parse OK | `yamllint values-*.yaml` |
| CI workflows sintaxis | ✅ PyYAML parse OK, 7+4 jobs estructurados | `actionlint .github/workflows/*.yml` |
| Helm template con nuevos values | ⏳ requiere Helm CLI | `helm template . -f values-sprbun.yaml` |
| OPA bundle merge real | ⏳ requiere archivos .rego reales | correr el script en tu repo |
| Production mode end-to-end | ⏳ requiere upstreams reales o testcontainers | entorno de staging |

---

## Pendientes post-Capa 4

| # | Item | Bloqueo |
|---|---|---|
| 1 | Drift analysis vs repo Windows v11.3 | Requiere subir el repo |
| 2 | Helm template patch para env vars de hardened clients | Trivial, ~40 LoC en deployment.yaml |
| 3 | Dashboard Grafana extra para shadow pilot delta (ARHIA HFL) | Diseño de paneles |
| 4 | Integration test real contra kind + testcontainers-mocked upstreams | CI job adicional (~1h de trabajo) |
| 5 | Runbook operacional por pilot (qué hacer si B12 dispara, quién recibe HIC tickets, etc.) | Contenido, no código |

---

## Estado acumulado del paquete ARHIAX v11.4

| Capa | Artefactos | Tests | Estado |
|---|---|---|---|
| 1 — Docs maestros | 7 .docx | — | ✅ |
| 2 — Runtime mínimo | 8 archivos | 21 pytest + 14 opa test | ✅ |
| 3 — 17 bundles restantes | 4 archivos | +95 pytest + +96 opa test | ✅ |
| 3b — Helm chart | 17 archivos | manual template review | ✅ |
| **4 — Hardened + Pilots + CI** | **11 archivos** | **+28 pytest (144 total)** | **✅** |
| 5 — Drift analysis | — | — | ⏳ |

**Total runtime code:** ~4,300 LoC Python + ~2,323 LoC Rego + ~1,000 LoC YAML
**Total tests:** 144 pytest + 110 opa test = **254 tests verdes**

---

*Generado en Capa 4, 2026-04-07. Anclado a TR-2026-034 MasterSpec y TR-2026-033 Phase3 TechExt.*

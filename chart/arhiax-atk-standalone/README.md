# arhiax-runtime

Helm chart para desplegar el runtime ARHIAX v11.4 (Agent Trust Kernel + 19 bundles OPA/Rego) en Kubernetes.

**Anclas de spec:** TR-2026-034 (MasterSpec) · TR-2026-033 (Phase 3) · TR-2026-034-ATK (ATK Reference Profile)
**Propietario:** Sinergia Consulting Group S.A.S. · Barranquilla, Colombia

---

## Qué instala

Un Pod con dos contenedores:

1. **ATK reference service** (`arhiax_atk_service.py`) — servidor uvicorn en `:8080` que implementa el envelope de 5 checks (Identity → Auth → Inspection → BBR → AutonomyGate) y la escalera de decisiones de 6 niveles.
2. **OPA sidecar** — `openpolicyagent/opa:0.70.0-rootless` en `:8181`, cargando los 19 bundles desde un ConfigMap montado en `/policies`.

ATK habla con OPA vía localhost (nunca sale del pod), minimizando latencia de cadena de políticas. Todas las decisiones emiten evidencia a EGA si `opa.decisionLogs.enabled: true`.

Recursos adicionales que instala:

| Recurso | Condición |
|---|---|
| `Deployment` | siempre |
| `Service` (ClusterIP) | siempre |
| `ConfigMap` de bundles (19 `.rego`) | `bundles.useConfigMap: true` |
| `ConfigMap` del dashboard Grafana | `metrics.grafanaDashboard.enabled: true` |
| `ServiceAccount` | `serviceAccount.create: true` |
| `PodDisruptionBudget` | `podDisruptionBudget.enabled: true` |
| `HorizontalPodAutoscaler` | `autoscaling.enabled: true` |
| `NetworkPolicy` (default-deny) | `networkPolicy.enabled: true` |
| `Ingress` | `ingress.enabled: true` |
| `ServiceMonitor` | `metrics.serviceMonitor.enabled: true` |

---

## Requisitos

- Kubernetes ≥ 1.28
- Helm ≥ 3.12
- Opcional: Prometheus Operator (para ServiceMonitor) y Grafana Operator (para descubrir el dashboard vía label `grafana_dashboard=1`)

---

## Quickstart

```bash
# Desde el directorio donde está este chart
helm install arhiax ./arhiax-runtime -n arhiax --create-namespace
```

Para un pilot SPRBUN (port logistics) con backends reales:

```bash
helm install arhiax-sprbun ./arhiax-runtime \
  -n arhiax-sprbun --create-namespace \
  --set image.tag=11.4.0-sprbun \
  --set atk.env.ARHIAX_MODE=production \
  --set atk.env.ARHIAX_AIM_URL=https://aim.sprbun.internal \
  --set atk.env.ARHIAX_EGA_URL=https://ega.sprbun.internal \
  --set opa.decisionLogs.enabled=true \
  --set opa.decisionLogs.service.url=https://ega.sprbun.internal/decisions \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.grafanaDashboard.enabled=true \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=arhiax-atk.sprbun.internal
```

---

## Observabilidad

El chart ship un dashboard Grafana con 6 paneles:

1. **Latencia del envelope** (p50/p95/p99) — alinea con el SLO de TR-2026-034-ATK §6 (p95 < 45ms)
2. **Decisiones por tipo** — 6-tier ladder: ALLOW / ALLOW_WITH_MONITORING / CHALLENGE / ESCALATE_TO_HIC / DENY / HARD_DENY
3. **Deny rate por bundle** — cuál de los 19 bundles está denegando más (útil para detectar misconfiguration o ataques dirigidos)
4. **HIC escalation rate** — % de envelopes enviados a humano (saludable < 0.5%)
5. **Evidence emission rate** — EGA-C01: debe ser no-cero siempre que haya tráfico
6. **OPA sidecar latency** — para desagregar latencia ATK vs política

---

## Seguridad

**Default posture: zero-trust.** El chart asume hostil-por-defecto:

- Contenedores **non-root** (uid 1000), `readOnlyRootFilesystem: true`, `drop: ALL` capabilities
- **NetworkPolicy default-deny**, con excepciones explícitas solo para Ingress controller y Prometheus
- `automountServiceAccountToken: false` — ATK no llama al API de k8s
- PodDisruptionBudget con `minAvailable: 2` — durante drain siempre hay quorum
- Pod Security Standard **restricted** compatible
- Dockerfile corre ambas suites de tests como build-gate (116 pytest; 110 tests Rego se validan localmente con `opa test`)

---

## Matriz de values clave

| Parámetro | Default | Descripción |
|---|---|---|
| `replicaCount` | `3` | Réplicas del Deployment (sin HPA) |
| `image.tag` | `""` (Chart.AppVersion) | Tag de la imagen ATK |
| `atk.env.ARHIAX_MODE` | `inmemory` | `inmemory` (dev/pilot) o `production` |
| `opa.enabled` | `true` | Desactivar si usas OPA externo |
| `opa.decisionLogs.enabled` | `false` | **Activar para cumplir EGA-C01** |
| `bundles.useConfigMap` | `true` | ConfigMap con los 19 .rego |
| `bundles.annotateChecksum` | `true` | Rollout automático al cambiar bundles |
| `autoscaling.enabled` | `false` | HPA v2 |
| `networkPolicy.enabled` | `true` | **Dejar en true en producción** |
| `podDisruptionBudget.enabled` | `true` | Protege quorum durante drains |
| `metrics.serviceMonitor.enabled` | `false` | Requiere Prometheus Operator |
| `metrics.grafanaDashboard.enabled` | `false` | Requiere Grafana Operator |

Ver `values.yaml` para la lista completa con comentarios inline.

---

## Actualización de bundles (proceso auditado)

1. Editar los `.rego` en `files/authz.rego` y/o `files/bundles_b01_b19.rego`
2. Correr localmente: `opa test files/*.rego` (debería dar 110 tests verdes)
3. `helm upgrade arhiax ./arhiax-runtime -n arhiax`
4. El checksum anotado dispara un rollout controlado (maxUnavailable: 0)
5. El sha256 nuevo del ConfigMap es la **nueva policy version** que aparecerá en todas las evidencias EGA subsiguientes (OPA-C02)

**Nunca editar el ConfigMap in-place** — rompe la continuidad de OPA-C02.

---

## Limitaciones conocidas

1. **Modo `inmemory` no es producción.** Los clientes AIM/BBR/EGA/AUT/HIC son reference impls in-memory. Para producción hace falta Capa 4 (hardened production clients), que reemplaza cada cliente por uno HTTP con auth real contra los backends de Sinergia.

2. **Métricas Prometheus pendientes de cableado en ATK.** El dashboard asume métricas `arhiax_envelope_latency_seconds_bucket`, `arhiax_envelope_decisions_total`, `arhiax_policy_denies_total`, `arhiax_evidence_emitted_total`. La instrumentación de estas métricas en `arhiax_atk_service.py` es parte del trabajo de hardening de Capa 4.

3. **El ServiceMonitor scrappea `/metrics` del puerto ATK**, no del puerto OPA. Las métricas OPA (`opa_rego_query_eval_duration_seconds_bucket`) requieren un segundo ServiceMonitor o un puerto adicional en el Service. No incluido para mantener el chart simple.

4. **No hay `Certificate` CRD de cert-manager**; el Ingress TLS se resuelve vía secretName en `ingress.tls[].secretName` — externo al chart.

---

## Soporte

Sinergia Consulting Group S.A.S.
Ray Miller, CEO · ray@sinergiaconsulting.co
Barranquilla, Colombia

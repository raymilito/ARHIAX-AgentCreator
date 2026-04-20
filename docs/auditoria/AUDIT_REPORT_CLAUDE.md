# ARHIA v11.4 (ARHIAX) — Reporte de Auditoría Técnica

**Fecha:** 2026-04-09
**IA Auditora:** Claude (Anthropic) — Modelo: claude-sonnet-4-6
**Herramienta:** Claude Code CLI
**Auditor humano:** Marcelo Ortega / IDEA CARIBE Agencia de Marketing
**Alcance:** Revisión completa del repositorio ARHIA ESTÁNDAR v11.4

> Este reporte fue generado por **Claude de Anthropic** como parte de un proceso de auditoría multi-IA. Para comparar con reportes de otras IAs, verificar el campo "IA Auditora" en el encabezado de cada documento.

---

## 1. Resumen Ejecutivo

ARHIA v11.4 es un framework de **gobernanza de IA agéntica** (Policy-as-Code), open-core, desarrollado por Sinergia Consulting Group S.A.S. (Barranquilla, Colombia). El proyecto presenta una arquitectura sólida, código limpio con zero dependencias externas, y un modelo de seguridad bien fundamentado.

**Estado general: Listo para publicación**, condicionado a completar las validaciones Helm pendientes.

---

## 2. Stack Tecnológico

| Componente | Lenguaje | Framework | Dependencias externas |
|---|---|---|---|
| Gateway (PEP) | Go 1.22 | stdlib net/http | **CERO** |
| Evidence Store | Go 1.22 | stdlib (JSONL + Merkle) | **CERO** |
| Correlator | Python 3 | stdlib | **CERO** (v1.0.0) |
| Policy Engine | OPA Rego | OPA 0.68.0-rootless | — |
| Orquestación | YAML | Kubernetes Helm v2 | >= k8s 1.24.0 |
| API Spec | OpenAPI | 3.0.3 | — |

> **Decisión arquitectónica**: Zero external dependencies por diseño. Mínima superficie CVE y máxima auditabilidad. Las dependencias Python (numpy, scipy, pandas) están reservadas para v1.1+.

---

## 3. Arquitectura del Sistema

```
Cliente → Gateway (Go) → OPA Engine (Rego policies) → Decisión ALLOW/DENY
                    ↓
             Evidence Store (Go, Merkle SHA-256, JSONL)
                    ↓
             Correlator (Python, stub en v1.0.0)
```

### Principios de diseño

- **Fail-closed**: Si OPA no responde → DENY automático
- **Fail-open en auditoría**: Si evidence store falla → log + continuar (trade-off documentado, PEP disponibilidad > auditing)
- **Deny-by-default**: Todas las políticas Rego niegan por defecto
- **Policy versioning**: Hash de bundle verificado en cada carga

### Políticas OPA (19 archivos, ~2.279 líneas Rego)

| Bloque | Dominio | Edición |
|---|---|---|
| B01 | OPA Core Policy Engine | Community |
| B02 | Data Classification | Community |
| B03 | ATK Envelope | Community |
| B04 | DTG Trajectory | Community |
| B05 | HIC Checkpoints | Community |
| B06 | Prompt Safety | Community |
| B07 | Autonomy Gates | Community |
| B08 | Output Filter | Community |
| B09 | Tool Governance | Community |
| B10 | Data Access | Community |
| B11 | AIBOM Lifecycle | Community |
| B12 | Network Boundary | Community |
| B13 | Compliance Reporting | Community |
| B14 | AIM Identity | **Enterprise** |
| B15 | AIM Lifecycle | **Enterprise** |
| B16 | AIM Permissions | **Enterprise** |
| B17 | DTG Correlation | **Enterprise** |
| B18 | EGA Evidence | **Enterprise** |
| B19 | EGA Retention | **Enterprise** |

### Imágenes Docker

```
ghcr.io/arhiax/arhiax-gateway:1.0.0        (~6 MB,  UID 10001, distroless)
ghcr.io/arhiax/arhiax-evidence-store:1.0.0  (~6 MB,  UID 10003, distroless)
ghcr.io/arhiax/arhiax-correlator:1.0.0      (~50 MB, UID 10004, distroless)
openpolicyagent/opa:0.68.0-rootless         (UID 10002)
```

### Endpoints del Gateway

| Endpoint | Método | Función |
|---|---|---|
| `/healthz` | GET | Liveness (200 siempre) |
| `/readyz` | GET | Readiness (verifica OPA + evidence store) |
| `/v1/decide` | POST | Decision API principal |
| `/metrics` | GET | Prometheus text format (puerto 9090) |

### Endpoints del Evidence Store

| Endpoint | Método | Función |
|---|---|---|
| `POST /v1/evidence` | POST | Append record |
| `GET /v1/evidence?limit=N` | GET | Últimos N records |
| `GET /v1/evidence/{id}` | GET | Fetch by ID |
| `GET /v1/head` | GET | Hash actual + count + timestamp |

---

## 4. Fortalezas

### Seguridad
- Imágenes distroless (sin shell, sin package manager, sin herramientas de debugging)
- Non-root UIDs en todos los contenedores (10001–10004)
- `readOnlyRootFilesystem: true` en todos los pods
- `allowPrivilegeEscalation: false`
- `seccompProfile: RuntimeDefault`
- Capabilities dropped: ALL
- JWT audience validation (`ARHIAX_JWT_AUDIENCES`)
- Mitigación Slowloris (`ReadHeaderTimeout: 5s`)
- Rate limiting configurable (`ARHIAX_RATE_LIMIT_RPS`, default 100)
- Request body size limit (`ARHIAX_MAX_REQUEST_BODY_BYTES`, default 1 MiB)
- Merkle SHA-256 chain en evidence store (detección de tampering)
- **Zero credenciales expuestas en el repositorio**

### Calidad de Código
- Structured JSON logging compatible con Loki/Vector (campo `component` en cada log)
- Métricas Prometheus hand-rolled sin client library externa
- `go vet` clean (sin dependencias que auditar)
- Python sintácticamente válido (compatible con `ast.parse`)
- Headers de archivo documentan decisiones arquitectónicas
- Separación clara de concerns: `opa/client.go`, `evidence/client.go`, `server/server.go`, `metrics/`

### Documentación
- OpenAPI 3.0 spec completa (50 KB) para API enterprise
- Control Registry JSON (36 controles, 8 subsistemas, tipos de evidencia, tiers de retención)
- Master Crosswalk YAML mapeando 5 frameworks de cumplimiento:
  - ARISE (AI Risk & Safety Evaluation)
  - OWASP ASI (AI Security Initiative)
  - CSA ATF (Cloud Security Alliance AI Trust Framework)
  - Singapore MGF (Model Governance Framework)
  - NIST CSF 2.0
- `VALIDATION.md` con estado de checks detallado
- `README.md` con design principles, env vars, y build instructions

### Operaciones
- Helm chart con 22 templates Kubernetes
- Liveness/readiness probes configurados en todos los componentes
- Resource limits definidos (CPU/memory requests y limits)
- HPA (Horizontal Pod Autoscaler) configurado para gateway y correlator
- PVC con `StorageRetentionPolicy: Retain` para evidence store
- NetworkPolicy templates incluidos
- CI/CD en `.github/workflows/build-images.yaml` con cosign keyless signing

---

## 5. Problemas Identificados

### Bugs ya corregidos (documentados en VALIDATION.md)

| Archivo | Problema | Estado |
|---|---|---|
| `templates/gateway-hpa.yaml` | Faltaba `{{ end }}` de cierre | ✅ Corregido |
| `charts/correlator/values.yaml` | Faltaban `nameOverride`, `fullnameOverride` | ✅ Corregido |
| `templates/evidence-store-pvc.yaml` | Multiline guard colapsada | ✅ Corregido |

### Validaciones Helm pendientes (BLOQUEANTES para publicación)

| Validación | Riesgo si no se ejecuta |
|---|---|
| `helm lint --strict` | Errores en Sprig functions, `toYaml` en nil, iconos mal referenciados |
| `helm template --set correlator.enabled=true` | Rendering errors con correlator habilitado |
| `helm template --set evidenceStore.driver=postgres` | Rendering errors con driver Postgres |
| `helm template --set opa.bundleServer.enabled=true` | Rendering errors con bundle server externo |
| `kubeconform` contra schema OpenAPI | Mismatches en `autoscaling/v2` en clusters legacy |
| Dry-run en cluster real | Fallo por PSA `restricted` profile o CNI NetworkPolicy issues |

### Empaquetado

- **Actual**: `tar czf` (funcional pero sin provenance)
- **Recomendado**: `helm package` + `cosign keyless sign` + SBOM attestation
- **Riesgo**: Sin SLSA build provenance en Artifact Hub

---

## 6. Deuda Técnica

| Item | Descripción | Impacto | Versión target |
|---|---|---|---|
| Correlator es stub | No hace anomaly detection real. Solo fetch + contadores. Sin D-TCG+ math | **Alto** | v1.1 |
| OPA policies en ConfigMap | Límite ~1 MB, sin encriptación, solo RBAC k8s como control | **Medio** | v1.1 |
| Postgres driver ausente | JSONL no es production-grade para alta disponibilidad | **Medio** | v1.1 |
| External witness faltante | Truncation attacks no detectados (Rekor-style transparency log) | **Medio** | v1.1 |
| Sin upgrade path documentado | Riesgo para early adopters al migrar de v1.0.0 a v1.1 | **Bajo** | v1.1 |
| Métricas Prometheus manuales | Mantenimiento crece con el proyecto al agregar nuevas métricas | **Bajo** | v1.2+ |
| Correlator schema v1.1 breaking | JSONL → Postgres requiere migración de datos de evidencia existente | **Bajo** | v1.1 |

### Roadmap v1.1+ (documentado en código)

- Real D-TCG+ math en correlator (numpy 2.1.*, scipy 1.14.*, pandas 2.2.*)
- Postgres driver para evidence store (`ARHIAX_EVIDENCE_DRIVER=postgres`)
- External witness integration (estilo Rekor transparency log)
- Per-record HMAC signing con HMAC-SHA256
- CLI `arhiax-evidence verify` para auditoría offline
- Bundles enterprise B14–B19 en distribución pública

---

## 7. Riesgos de Seguridad Residuales

### Riesgo 1: Truncation Attack (Severidad: Media)

El evidence store detecta tampering (modificación de records existentes via Merkle chain) pero **NO detecta truncación de tail** (eliminación de los últimos N records).

**Mitigación recomendada**: External witness/checkpoint service (v1.1). Documentado como limitación conocida.

### Riesgo 2: Evidence Store Fail-Open (Severidad: Baja)

Si el evidence write falla, la decisión se retorna igualmente al cliente. La acción queda sin auditar.

**Trade-off**: PEP disponibilidad > auditing completeness. Compensado por logging structured + alertas Prometheus. Documentado como decisión de diseño.

### Riesgo 3: OPA Bundle via ConfigMap (Severidad: Baja)

En modo default, las políticas se sirven desde ConfigMap. Límite ~1 MB, sin encriptación at-rest, control exclusivamente vía RBAC de Kubernetes.

**Mitigación**: Configurar `opa.bundleServer.enabled=true` con servidor externo autenticado para deployments enterprise.

### Riesgo 4: Sin Request Signing en Community Runtime (Severidad: Baja)

La enterprise API requiere `X-ARHIAX-Signature` (HMAC-SHA256). El runtime community no lo implementa en v1.0.0.

**Scope**: Aplica solo a clientes que consuman la enterprise API directamente sin el SDK provisto.

### Riesgo 5: Cluster Domain Hardcoded (Severidad: Muy Baja)

`global.clusterDomain: cluster.local` es el default de Kubernetes pero no está parametrizado para clusters con custom domains.

**Mitigación**: Override vía `--set global.clusterDomain=<domain>` en helm install.

---

## 8. Modelo Open-Core

| Aspecto | Community Edition | Enterprise Edition |
|---|---|---|
| Licencia | Apache 2.0 | Comercial |
| Políticas incluidas | B01–B13 (13 bundles) | B01–B19 (19 bundles) |
| Threat Intelligence | No | Sí |
| Behavioral baselines | No | Sí |
| Multi-tenant RBAC | No | Sí (B14–B16) |
| Request signing | No | Sí (HMAC-SHA256) |
| Enterprise API | No | Sí (OpenAPI 50 KB) |
| Vendor soporte | Comunidad | SLA contractual |

---

## 9. Prioridades Antes de Publicación

```
Prioridad 1 (Bloqueante)
├── helm lint --strict
├── helm template con todas las variaciones
│   ├── correlator.enabled=true
│   ├── evidenceStore.driver=postgres
│   └── opa.bundleServer.enabled=true
└── kubeconform contra schema OpenAPI

Prioridad 2 (Importante)
├── helm package (reemplazar tar czf)
├── cosign keyless sign en CI
└── SBOM attestation

Prioridad 3 (Antes de GA)
├── Documentar upgrade path v1.0.0 → v1.1
├── Dry-run en cluster real (PSA restricted profile)
└── NetworkPolicy validation con CNI real (Cilium/Calico)
```

---

## 10. Métricas del Repositorio

| Métrica | Valor |
|---|---|
| Total de archivos | ~175 |
| Líneas de código Go (aprox.) | ~1.400 |
| Líneas de código Python (aprox.) | ~800 |
| Líneas de políticas Rego | ~2.279 |
| Líneas de configuración Helm | ~421 (values.yaml) |
| Templates Kubernetes | 22 archivos |
| Archivos de documentación | 8+ |
| Dependencias externas en runtime | **0** |

---

## 11. Veredicto Final

| Dimensión | Calificación | Notas |
|---|---|---|
| Arquitectura | Excelente | Zero deps, fail-closed, modular, bien separada |
| Seguridad | Muy buena | Distroless, non-root, Merkle chain, JWT, rate limiting |
| Calidad de código | Muy buena | Structured logs, go vet clean, documentación inline |
| Documentación | Excelente | OpenAPI, Crosswalk, Control Registry, VALIDATION.md |
| Testing | Aceptable | `make test` + `make smoke` pero sin CI continuo ejecutado |
| Validación Helm | Pendiente | Bloqueante para publicación en Artifact Hub |
| Deuda técnica | Baja-Media | Correlator stub es el item más relevante |
| Madurez comercial | Buena | Modelo open-core bien estructurado, pricing documentado |

> **Conclusión**: Proyecto sólido y publication-ready condicionado a completar las validaciones Helm (`helm lint`, `helm template`, `kubeconform`). La arquitectura es correcta, el código limpio, y las decisiones de diseño están bien fundamentadas y documentadas. El mayor riesgo técnico actual es el Correlator stub (zero anomaly detection en v1.0.0), que debe comunicarse claramente en el changelog de publicación.

---

*Reporte generado el 2026-04-09 por **Claude (Anthropic)**, modelo claude-sonnet-4-6, mediante revisión automatizada de código fuente, configuración, políticas y documentación del repositorio. Parte de un proceso de auditoría multi-IA coordinado por IDEA CARIBE Agencia de Marketing.*

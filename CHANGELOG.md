# Changelog — ARHIAX AgentCreator

Todos los cambios notables se documentan en este archivo.

---

## [1.0.0] — 2026-04-19

### Lanzamiento inicial

#### Nuevo — Servicios
- **Creator API** (`:8300`): Fábrica de agentes gobernados. Orquesta AIM y AUT para crear agentes completamente provisionados con una sola llamada API.
- **AIM Service** (`:8200`): Agent Identity Management. Emite credenciales de 10 campos con cadena HMAC-SHA256, gestión completa del ciclo de vida (ACTIVE → ROTATING → SUSPENDED → RETIRED).
- **AUT Service** (`:8201`): Autonomy Management. Escala A0–A4 con 5 puertas de promoción, degradación automática por desviación sigma, historial completo de eventos.
- **BBR Service** (`:8202`): Behavioral Baseline Registry. Registro de observaciones conductuales, cálculo de desviación sigma contra línea base histórica (mínimo 5 observaciones).
- **HIC Service** (`:8203`): Human-in-the-Loop Checkpoints. Gestión de tickets de aprobación con SLA por severidad (5min → 24hrs), notificaciones webhook, estados PENDING/APPROVED/REJECTED/SLA_EXPIRED.
- **Gateway** (`:8080`): Policy Enforcement Point en Python. Detección local de inyecciones, consulta OPA, registro de evidencia, 6 outcomes diferenciados.
- **Evidence Store** (`:8090`): Ledger JSONL append-only con cadena HMAC-SHA256. Verificación de integridad completa via `/v1/evidence/verify/chain`.

#### Nuevo — SDK Python
- Clase `ARHIAXAgent` base para agentes gobernados
- Decorador `@governed_tool` para gobernanza automática de herramientas
- `invoke_model()` con gobernanza automática de llamadas LLM
- `access_data()` para acceso gobernado a datos
- `call_agent()` para llamadas inter-agente gobernadas
- `GatewayClient` con circuit breaker y retry exponencial
- `AIMClient`, `HICClient`, `BBRClient`
- Excepciones tipadas: `ARHIAXDenied`, `ARHIAXEscalated`, `ARHIAXInjectionDetected`, `ARHIAXCredentialExpired`, `ARHIAXToolNotPermitted`, `ARHIAXServiceUnavailable`
- Context manager (`async with`) para carga automática de credencial

#### Nuevo — Runtime
- 39 archivos Rego de políticas ARHIAX (19 bundles, versiones v1 y v2)
- Política OPA base `main.rego` para el nuevo Gateway Python
- OPA 0.68.0-rootless como imagen oficial

#### Nuevo — Infraestructura
- `docker-compose.yml` completo con 8 servicios, red interna `arhiax-net`, 5 volúmenes persistentes
- Dockerfiles Python 3.12-slim para todos los servicios
- Health checks y readiness probes en todos los servicios
- `.env.example` con todas las variables documentadas

#### Nuevo — Documentación
- `README.md` — Visión general, inicio rápido, arquitectura
- `ARCHITECTURE.md` — Diagramas ASCII completos de flujos de creación y operación
- `API_REFERENCE.md` — Todos los endpoints con campos, tipos y ejemplos
- `DEPLOYMENT.md` — Local, servidor Linux, backups, monitoreo, troubleshooting
- `SECURITY.md` — Modelo de seguridad, checklist pre-producción
- `CHANGELOG.md` — Este archivo
- `CONTRIBUTING.md` — Guía de contribución
- README individual de cada servicio (7 archivos)
- README del SDK con guía completa de uso

#### Heredado
- 19 bundles OPA/Rego de políticas de gobernanza probadas
- Especificación de credencial de 10 campos (TR-2026-034-A §4.3)
- Escala de autonomía A0–A4 con umbrales sigma documentados
- 5 puertas de promoción G1–G5
- 6 outcomes de gobernanza
- Tipos de evidencia y tiers de retención (T1=7yr, T2=3yr, T3=1yr)
- Modelo de detección de inyecciones (patrones de B03_atk_envelope.rego)

---

## Roadmap

### [1.1.0] — Próximo
- Integración completa de C09 INTERP Bridge (señales de interpretabilidad mecanística)
- BBR con detección de drift más sofisticada (continuous bootstrap-based CI)
- Endpoint de webhook en HIC para flujo de aprobación bidireccional
- Correlator Python (DTG-C03 CLAS) como servicio independiente

### [1.2.0] — Futuro
- SDK para TypeScript/Node.js
- Dashboard web para visualizar agentes, decisiones y tickets HIC
- Integración con HashiCorp Vault para gestión de secretos
- Export de compliance report (SOC 2, ISO 27001)
- Helm chart para Kubernetes

### [2.0.0] — Visión
- Multi-tenancy: múltiples organizaciones en el mismo stack
- Marketplace de bundles OPA por industria (finanzas, salud, retail)
- SDK en Go, Java y Rust
- Federación entre instancias ARHIAX (multi-región)

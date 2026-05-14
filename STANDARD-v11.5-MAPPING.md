# STANDARD-v11.5-MAPPING - ARHIAX AgentCreator

Documento de trazabilidad canonica contra el estandar ARHIA(X) v11.5.

## Control De Version

| Campo | Valor |
| --- | --- |
| Documento | STANDARD-v11.5-MAPPING |
| Repositorio | ARHIAX-AgentCreator |
| TR de origen | TR-AGC-001 |
| Version | v1.0.0 |
| Fecha | 2026-05-14 |
| Capa del moat | Layer 2 - runtime ARHIA |
| Rama objetivo | main |

Este repositorio implementa la capa de runtime gobernado para creacion y ejecucion de agentes ARHIAX. No sustituye capas corporativas externas como IAM enterprise, SIEM central, Vault productivo, firma de releases o gestion legal de cumplimiento; se integra con ellas mediante variables, endpoints, certificados y evidencia.

## Alcance

El alcance validado cubre:

| Dominio | Implementacion |
| --- | --- |
| Fabrica de agentes | `services/creator-api/main.py` |
| Identidad de agente | `services/aim-service/main.py` |
| Autonomia A0-A4 | `services/aut-service/main.py` |
| Policy Enforcement Point | `services/gateway/main.py` |
| Tokens efimeros | `services/credential-broker/main.py`, `sdk/python/arhiax/client.py` |
| SDK gobernado | `sdk/python/arhiax/agent.py` |
| Evidencia | `services/evidence-store/main.py` |
| Politicas OPA/Rego | `runtime/opa/main.rego`, `runtime/bundles/v1`, `runtime/bundles/v2` |
| Despliegue local | `docker-compose.yml`, `scripts/generate-certs.sh` |

## Componentes Canonicos v11.5

Los estados permitidos son `PRESENTE`, `PARCIAL`, `AUSENTE-DIFERIDO` y `AUSENTE-NO-APLICA`.

| Orden | Componente canonico | Estado | Evidencia | Observacion / sucesor |
| ---: | --- | --- | --- | --- |
| 01 | AIM - Agent Identity Management | PRESENTE | `services/aim-service/main.py`, `/v1/agents/register`, `/v1/credentials/{agent_id}` | Identidad, lifecycle, credencial, HMAC, operaciones permitidas y `security_profile`. |
| 02 | DTG - Decision Trace Graph | PARCIAL | `runtime/bundles/v1/dtg`, `runtime/bundles/v2/dtg`, `runtime/reference-images/images/correlator` | Hay bundles y referencia de correlacion; falta servicio DTG productivo integrado al compose. Sucesor: TR-AGC-002. |
| 03 | ATK - Agent Tool Kernel | PRESENTE | `sdk/python/arhiax/agent.py`, `services/gateway/main.py`, `runtime/atk/arhiax_atk_service.py` | `@governed_tool`, Gateway PEP, OPA y validacion de herramienta por scope/audience. |
| 04 | AUT - Autonomy Management | PRESENTE | `services/aut-service/main.py`, `/v1/autonomy/register`, `/v1/autonomy/check` | A0-A4, gates de promocion, degradacion y bloqueo de agentes no registrados. |
| 05 | HIC - Human-in-the-Loop Checkpoints | PRESENTE | `services/hic-service/main.py`, `sdk/python/arhiax/agent.py` | Tickets, aprobacion/rechazo, SLA, step-up bloqueante desde SDK. |
| 06 | BBR - Behavioral Baseline Registry | PRESENTE | `services/bbr-service/main.py`, `/v1/baseline/{agent_id}/observe` | Observaciones, baseline, sigma y WAL SQLite para concurrencia inicial. |
| 07 | EGA - Evidence Graph / Audit Ledger | PARCIAL | `services/evidence-store/main.py`, `/v1/evidence`, `/v1/evidence/verify/chain` | Ledger JSONL HMAC y reporte de cumplimiento. Falta grafo semantico completo. Sucesor: TR-AGC-003. |
| 08 | PRM - Policy Release Management | AUSENTE-DIFERIDO | `runtime/bundles/v1/MANIFEST.json`, `runtime/bundles/v2/MANIFEST.json` | Hay manifiestos versionados, no hay pipeline de firma/publicacion de bundles. Sucesor: TR-AGC-004. |
| 09 | INTERP Bridge | PARCIAL | `runtime/c09`, `runtime/c09/policy/interp.rego`, `specs/v11.5/interp-ev-1.0.schema.json` | Implementacion de referencia C09 presente; falta cableado al Gateway runtime. Sucesor: TR-AGC-005. |
| 10 | KSW - Kill Switch | PARCIAL | `services/gateway/main.py`, `/v1/org/halt`, `/v1/org/resume`, `/v1/org/halt/status` | Kill-switch organizacional persistible en Redis. Falta control granular por dominio/agente. Sucesor: TR-AGC-006. |
| 11 | mTLS Mesh Boundary | PRESENTE | `docker-compose.yml`, `scripts/generate-certs.sh`, `certs/`, `ARHIAX_CA_CERT` | Certificados de servicio y soporte cliente mTLS en SDK/servicios. |
| 12 | SIEM / Observability | PARCIAL | `services/gateway/main.py`, `/metrics`, `/v1/anomalies` | Metricas Prometheus y snapshot de anomalias. Falta conector SIEM administrado. Sucesor: TR-AGC-007. |
| 13 | Compliance Dossier Generator | PARCIAL | `services/evidence-store/main.py`, `/v1/compliance/report` | Reporte agregado desde ledger. Falta dossier formal exportable y firma. Sucesor: TR-AGC-008. |
| 14 | Pattern Library & Templates | PARCIAL | `services/creator-api/main.py`, `sdk/python/README.md`, `bootstrap_config` | Bootstrap seguro y SDK. Falta libreria completa de plantillas certificadas. Sucesor: TR-AGC-009. |

## Bundles OPA/Rego

El runtime contiene 19 bundles B01-B19 en `runtime/bundles/v1` y `runtime/bundles/v2`, con pruebas en `runtime/bundles/bundles_b01_b19_test.rego`.

| Bundle | Dominio | Evidencia |
| --- | --- | --- |
| B01 | OPA core | `runtime/bundles/v1/opa_engine/B01_opa_core.rego` |
| B02 | Data classification | `runtime/bundles/v1/domain/B02_data_classification.rego` |
| B03 | ATK envelope | `runtime/bundles/v1/atk/B03_atk_envelope.rego` |
| B04 | DTG trajectory | `runtime/bundles/v1/dtg/B04_dtg_trajectory.rego` |
| B05 | HIC checkpoints | `runtime/bundles/v1/hic/B05_hic_checkpoints.rego` |
| B06 | Prompt safety | `runtime/bundles/v1/domain/B06_prompt_safety.rego` |
| B07 | Autonomy gates | `runtime/bundles/v1/aut/B07_autonomy_gates.rego` |
| B08 | Output filter | `runtime/bundles/v1/domain/B08_output_filter.rego` |
| B09 | Tool governance | `runtime/bundles/v1/domain/B09_tool_governance.rego` |
| B10 | Data access | `runtime/bundles/v1/domain/B10_data_access.rego` |
| B11 | AIBOM lifecycle | `runtime/bundles/v1/aibom/B11_aibom_lifecycle.rego` |
| B12 | Network boundary | `runtime/bundles/v1/domain/B12_network_boundary.rego` |
| B13 | Compliance reporting | `runtime/bundles/v1/domain/B13_compliance_reporting.rego` |
| B14 | AIM identity | `runtime/bundles/v1/aim/B14_aim_identity.rego` |
| B15 | AIM lifecycle | `runtime/bundles/v1/aim/B15_aim_lifecycle.rego` |
| B16 | AIM permissions | `runtime/bundles/v1/aim/B16_aim_permissions.rego` |
| B17 | DTG correlation | `runtime/bundles/v1/dtg/B17_dtg_correlation.rego` |
| B18 | EGA evidence | `runtime/bundles/v1/ega/B18_ega_evidence.rego` |
| B19 | EGA retention | `runtime/bundles/v1/ega/B19_ega_retention.rego` |

## Extensiones Al v11.5

Estas extensiones elevan la postura de seguridad del AgentCreator sin romper el modelo canonico v11.5.

| Extension | Estado | Evidencia | Valor |
| --- | --- | --- | --- |
| Credential Broker | PRESENTE | `services/credential-broker/main.py`, `docker-compose.yml` | Emite tokens efimeros ES256 por accion, no tokens amplios. |
| Ephemeral tokens layer | PRESENTE | `services/gateway/main.py`, `sdk/python/arhiax/client.py` | Valida `exp`, `nbf`, `aud`, `jti`, `scope`, `invocation_id`, `context_binding` y DPoP. |
| SDK `@governed_tool` | PRESENTE | `sdk/python/arhiax/agent.py` | Toda herramienta pasa por Gateway, HIC, Broker y evidencia. |
| `security_profile` | PRESENTE | `services/aim-service/main.py`, `services/creator-api/main.py` | Perfil por agente para `token_mode`, TTL, broker enforcement, HIC y zero-token-in-context. |
| Signed agent credential proof | PRESENTE | `services/credential-broker/main.py`, `sdk/python/arhiax/client.py` | Reemplaza el HMAC crudo como prueba primaria; incluye nonce, timestamp y firma HMAC canonica. |
| SQLite WAL runtime | PRESENTE | `services/aim-service/main.py`, `services/aut-service/main.py`, `services/bbr-service/main.py`, `services/hic-service/main.py`, `services/evidence-store/main.py` | Mejora concurrencia local y test isolation; PostgreSQL queda recomendado para alta carga. |
| Safe bootstrap config | PRESENTE | `services/creator-api/main.py` | El bootstrap entrega valores via `bootstrap_config` y literales seguros, no interpolacion insegura. |

## Crosswalk Preliminar De 36 Controles

Este crosswalk es tecnico y preliminar; no sustituye asesoria legal ni certificacion externa.

| Control | Nombre | NIST AI RMF | ISO/IEC 42001:2023 | EU AI Act |
| --- | --- | --- | --- | --- |
| C01 | Gobierno de agentes | Govern | AIMS governance | Art. 9 |
| C02 | Clasificacion de riesgo | Map | Risk assessment | Art. 9 |
| C03 | Identidad unica | Govern/Manage | Asset and responsibility controls | Art. 12 |
| C04 | Lifecycle de credencial | Manage | Operational control | Art. 9, 15 |
| C05 | Minimo privilegio | Manage | Access control | Art. 9, 15 |
| C06 | Autonomia A0-A4 | Map/Measure | AI system impact criteria | Art. 14 |
| C07 | Puertas de promocion | Manage | Change and release governance | Art. 9 |
| C08 | Degradacion automatica | Manage | Incident response | Art. 15 |
| C09 | Human-in-the-loop | Govern/Manage | Human oversight process | Art. 14 |
| C10 | Evidencia append-only | Measure/Manage | Records and auditability | Art. 12 |
| C11 | Integridad HMAC | Measure | Evidence integrity | Art. 12 |
| C12 | Deny-by-default | Manage | Operational safeguards | Art. 9 |
| C13 | Politicas OPA/Rego | Govern/Manage | Control implementation | Art. 9 |
| C14 | Seguridad de prompts | Measure/Manage | Data and operational controls | Art. 15 |
| C15 | Filtro de salidas | Measure/Manage | Output control | Art. 15 |
| C16 | Tool governance | Manage | Operational control | Art. 9, 15 |
| C17 | Tokens efimeros | Manage | Access/session control | Art. 15 |
| C18 | DPoP proof-of-possession | Manage | Cryptographic control | Art. 15 |
| C19 | Revocacion por JTI | Manage | Incident containment | Art. 15 |
| C20 | Replay protection | Manage | Security monitoring | Art. 15 |
| C21 | mTLS interno | Manage | Network security | Art. 15 |
| C22 | No tokens en prompt | Manage | Data minimization | Art. 10, 15 |
| C23 | Observabilidad SIEM | Measure/Manage | Monitoring | Art. 12, 15 |
| C24 | Anomalias de audiencia | Measure | Runtime monitoring | Art. 15 |
| C25 | Kill switch | Manage | Emergency response | Art. 14, 15 |
| C26 | Idempotencia segura | Manage | Operational resilience | Art. 15 |
| C27 | Baseline conductual | Measure | Monitoring and measurement | Art. 15 |
| C28 | Sigma deviation | Measure | Performance monitoring | Art. 15 |
| C29 | Compliance report | Govern/Measure | Documentation and records | Art. 11, 12 |
| C30 | Retencion de evidencia | Govern/Manage | Record retention | Art. 12 |
| C31 | Interpretability bridge | Measure | Explainability support | Art. 13 |
| C32 | Data classification | Map | Data governance | Art. 10 |
| C33 | Secure bootstrap | Manage | Secure development | Art. 15 |
| C34 | Secretos via Vault | Manage | Secrets management | Art. 15 |
| C35 | Tests por servicio | Measure | Verification and validation | Art. 9, 15 |
| C36 | Despliegue reproducible | Manage | Operational planning | Art. 15 |

## Gaps Y Roadmap

| Gap | Riesgo | Sucesor |
| --- | --- | --- |
| DTG como servicio productivo | Trazabilidad semantica incompleta | TR-AGC-002 |
| EGA graph/dossier completo | Evidencia no enriquecida como grafo | TR-AGC-003 |
| Firma y release management de bundles | Riesgo de supply chain de politicas | TR-AGC-004 |
| C09 integrado al Gateway | Interpretabilidad no bloqueante en runtime | TR-AGC-005 |
| Kill-switch granular | Halt solo organizacional | TR-AGC-006 |
| SIEM connector | Alertas sin exportador administrado | TR-AGC-007 |
| Dossier exportable firmado | Cumplimiento no empaquetado formalmente | TR-AGC-008 |
| Plantillas certificadas | Biblioteca de agentes aun parcial | TR-AGC-009 |
| PostgreSQL para alta concurrencia | SQLite puede limitar escritura intensiva | TR-AGC-010 |
| Vault obligatorio en produccion | Fallback env var aceptable solo para dev | TR-AGC-011 |

## Changelog

| Version | Fecha | Cambio |
| --- | --- | --- |
| v1.0.0 | 2026-04-19 | Primer release publico del AgentCreator. |
| v1.1.0 | 2026-05-13 | Capa de tokens efimeros, Broker, DPoP, mTLS, Redis y HIC step-up. |
| v1.2.0 | 2026-05-14 | Mapeo v11.5, pruebas de Broker, signed agent proof, SQLite WAL y bootstrap seguro. |

## Firma

| Rol | Nombre |
| --- | --- |
| Arquitecto revisor | Ray Miller |
| Ejecutor tecnico | Harold Combita |
| Fecha de cierre | 2026-05-14 |
| SHA-256 | 9362e6387d1dc84915e886cf5759d3f3271319466b90bfda39e3d5ef1c6b2b4f |

Metodo de hash: SHA-256 del contenido UTF-8 de este archivo excluyendo unicamente la linea `| SHA-256 | ... |`.

# ADR-ARHIAX-001 - Arquitectura de Tokens Efimeros y Delegacion Gobernada

**Owner:** Sinergia Consulting Group S.A.S.  
**Status:** Proposed  
**Date:** 2026-05-13  
**Decision Scope:** ARHIAX CM, ARHIA-DX, AgentCreator, runtime gobernado, microservicios internos y herramientas invocadas por agentes

---

## Contexto

ARHIAX opera en un entorno donde los tokens efimeros pueden autorizar lecturas sensibles, mutaciones de alto impacto, invocaciones de herramientas por agentes, operaciones catastrales y acciones transaccionales en microservicios internos.

Aunque dichas credenciales tengan ventanas de validez cortas, su compromiso sigue siendo materialmente riesgoso por cinco razones estructurales:

1. una ventana breve sigue siendo suficiente para ejecutar una accion sensible
2. un bearer token robado puede ser reutilizado dentro de su vigencia
3. los servicios internos tienden a sobreconfiar en validaciones aguas arriba
4. un modelo LLM puede exfiltrar material de autorizacion si este aparece en contexto
5. la validez criptografica del token no garantiza que la accion sea legal en el contexto de negocio

El enfoque tradicional de "emitir JWT cortos y validar exp" es insuficiente para la postura de seguridad objetivo de ARHIAX. Se requiere una arquitectura completa que desacople identidad, delegacion, ejecucion y evidencia.

---

## Decision

ARHIAX adopta una arquitectura de **delegacion gobernada para tokens efimeros** basada en los siguientes pilares:

1. **Zero-token-in-context**
   Ningun token operacional o secreto equivalente puede exponerse al modelo LLM, a su memoria conversacional o a descripciones de tools visibles para el modelo.

2. **Credential Broker como plano de delegacion**
   Toda credencial efimera para operaciones sensibles o tool calls de agentes debe emitirse mediante un Credential Broker dedicado que entregue tokens por accion, audiencia y contexto.

3. **Proof-of-possession por defecto cuando sea viable**
   Para clientes externos y flujos compatibles se utilizara `DPoP`; para trafico interno de alta confianza se reforzara con `mTLS` e identidad de workload.

4. **Validacion local obligatoria en cada servicio**
   Todo servicio validara firma, algoritmo, `iss`, `aud`, `exp`, `nbf` cuando aplique, `jti` y, si existe, la prueba de posesion.

5. **Autorizacion contextual ademas de autenticacion**
   Ninguna operacion sensible sera autorizada unicamente por la validez del token. El backend verificara propiedad, flujo, jurisdiccion, nivel de autonomia y requisitos de aprobacion.

6. **Revocacion hibrida**
   ARHIAX aceptara estado operativo para elevar control: validacion local + cache de `jti` revocados + introspection o verificacion reforzada en operaciones de alto impacto.

7. **Telemetria y evidencia forense**
   Toda emision, uso, denegacion y anomalia de credenciales efimeras generara evidencia correlacionable con actor, recurso, servicio y resultado.

---

## Razonamiento

La decision se adopta porque:

- el bearer token puro es incompatible con una arquitectura multiagente de alta sensibilidad
- el mayor riesgo en ARHIA-DX no es solo el MITM clasico, sino la exfiltracion desde el plano LLM o desde adaptadores de tools mal disenados
- la validacion unicamente en gateway crea un punto unico de fallo y de confianza excesiva
- las operaciones catastrales y equivalentes requieren autorizacion contextual, no solo identidad autenticada
- la revocacion real exige aceptar algo de estado, especialmente en ventanas cortas donde la respuesta a incidente importa mas que la pureza del modelo stateless

El Credential Broker es la pieza diferenciadora porque reduce la superficie de exposicion: ni el usuario ni el agente ni las herramientas necesitan cargar credenciales amplias y reutilizables para operar. Cada accion recibe solo la autorizacion estrictamente necesaria.

---

## Arquitectura decidida

El patron normativo de referencia sera:

```text
Usuario o Servicio
  -> Identity Provider
  -> API Gateway
  -> Policy Layer
  -> Credential Broker
  -> Token Efimero de Proposito Unico
  -> Servicio o Tool Destino
  -> Evidence and Monitoring Plane
```

En ARHIA-DX:

- el modelo decide la intencion
- el orquestador valida forma y politica
- el broker emite la credencial minima
- el adaptador ejecuta la llamada
- la respuesta vuelve saneada al modelo

---

## Consecuencias

### Positivas

- menor valor operativo de un token filtrado
- reduccion fuerte del riesgo de replay
- mejor contencion del movimiento lateral
- aislamiento del plano LLM respecto del plano de credenciales
- trazabilidad forense superior
- mayor compatibilidad con dominios regulados y operaciones juridicamente sensibles

### Costos y trade-offs

- mayor complejidad arquitectonica
- necesidad de operar un Credential Broker
- introduccion deliberada de estado para revocacion y deteccion
- mayor trabajo de integracion entre gateway, policy engine, broker y tools
- posibles impactos de latencia en operaciones de alta sensibilidad

### Riesgos residuales

- DPoP no elimina por completo el replay si la implementacion es defectuosa
- un adaptador de tool mal construido puede seguir exponiendo secretos en errores o respuestas
- la autorizacion contextual puede degradarse si las fuentes de verdad de negocio no son consistentes
- la observabilidad puede generar falsos positivos si no se calibran bien las reglas

---

## Requisitos normativos derivados

Los siguientes requisitos pasan a ser normativos para la arquitectura objetivo:

1. firma asimetrica obligatoria para tokens operacionales
2. prohibicion de tokens en query params
3. prohibicion de secretos en prompts o contexto visible por el modelo
4. validacion de `aud` exacta por servicio
5. `jti` obligatorio para tokens efimeros sensibles
6. TTL corto por clase de operacion
7. mTLS en trafico interno sensible
8. salida de tools saneada antes de regresar al modelo
9. revocacion operativa para credenciales de alto impacto
10. correlacion forense entre `jti` y objeto de negocio

---

## Alternativas consideradas

### Alternativa A - Bearer JWT corto sin broker

Se descarta como arquitectura objetivo porque:

- deja demasiado valor concentrado en el token
- no aísla el plano LLM
- complica la delegacion granular
- es debil ante replay y movimiento lateral

### Alternativa B - Solo introspection centralizada

Se descarta como unica estrategia porque:

- incrementa dependencia de disponibilidad central
- introduce latencia en todo el trafico
- no resuelve por si sola el problema de exposicion al modelo

### Alternativa C - Solo mTLS interno y gateway fuerte

Se descarta como solucion suficiente porque:

- protege trayecto interno, pero no la delegacion a herramientas ni el contexto LLM
- sigue dejando sobreconfianza en validaciones aguas arriba

---

## Impacto de implementacion

### Corto plazo

- endurecimiento de validacion en servicios
- limpieza de logs, prompts y errores
- reduccion de TTL
- revocacion basica por `jti`

### Mediano plazo

- despliegue de mTLS
- adopcion de DPoP
- separacion de identidades humanas, de agente y de servicio

### Largo plazo

- despliegue de Credential Broker
- migracion completa a credenciales por accion
- step-up auth y dual approval para actos criticos
- red team recurrente sobre replay, lateral movement y prompt injection

---

## Estado de adopcion recomendado

Esta decision debe tratarse como arquitectura objetivo obligatoria para:

- nuevos servicios de ARHIAX
- integraciones nuevas de ARHIA-DX
- tool adapters de agentes
- operaciones catastrales y equivalentes de impacto medio o alto

Para componentes legados, se permite adopcion por fases, pero con un objetivo explicito de convergencia.

---

## Referencias internas

- `docs/ARHIAX_Arquitectura_de_Seguridad_para_Tokens_Efimeros_ES.md`
- `docs/ARHIAX_Ephemeral_Token_Security_Architecture.md`
- `SECURITY.md`
- `ARCHITECTURE.md`

---

## Decision summary

ARHIAX adopta una arquitectura de delegacion gobernada para tokens efimeros en la que las credenciales son de vida corta, de proposito unico, vinculadas a posesion cuando sea posible, emitidas por broker, validadas en cada frontera, autorizadas segun contexto de negocio, aisladas del plano LLM y trazables de extremo a extremo.

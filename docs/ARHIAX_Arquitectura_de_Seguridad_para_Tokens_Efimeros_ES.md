# ARHIAX Arquitectura de Seguridad para Tokens Efimeros

**Owner:** Sinergia Consulting Group S.A.S.  
**Estado:** Borrador ejecutivo detallado  
**Fecha:** 2026-05-13  
**Ambito:** ARHIAX CM, ARHIA-DX, AgentCreator, runtime gobernado, microservicios internos y operaciones catastrales o de alto impacto

---

## 1. Proposito

Este documento define la arquitectura objetivo de ARHIAX para minimizar el riesgo de compromiso, reutilizacion, desvio de uso y exfiltracion de tokens efimeros en plataformas multiagente y entornos de ejecucion gobernados.

La tesis central es que, en una arquitectura ARHIAX de nivel empresarial, la seguridad no puede descansar en la fortaleza intrinseca del token. Debe descansar en una cadena completa de controles de emision, delegacion, validacion, autorizacion contextual, aislamiento del plano LLM, trazabilidad forense y revocacion operativa.

En consecuencia, el objetivo de diseno no es solo endurecer el token, sino lograr que:

- un token filtrado tenga valor operativo minimo
- un token robado no sea reutilizable fuera de su contexto
- un token valido no baste por si solo para ejecutar un acto sensible
- toda emision y todo uso de credenciales deje evidencia auditable
- el modelo LLM nunca tenga acceso directo al material de autorizacion

---

## 2. Declaracion del problema

En ARHIAX CM y ARHIA-DX, un token efimero puede representar autorizacion temporal para:

- leer o mutar informacion catastral
- ejecutar una accion de agente sobre una herramienta
- invocar un microservicio con privilegios sensibles
- operar sobre un expediente, predio, acto o transaccion regulada

Ese caracter temporal no elimina el riesgo. En escenarios de alto impacto, incluso una ventana de segundos o pocos minutos es suficiente para:

- materializar una lectura no autorizada
- activar una mutacion con consecuencias juridicas u operativas
- desplazar lateralmente un privilegio dentro de la malla de servicios
- exfiltrar informacion desde una cadena multiagente
- contaminar la trazabilidad si la operacion ocurre sin correlacion forense adecuada

Por tanto, el riesgo de tokens efimeros debe tratarse como un problema de arquitectura y gobernanza, no como un simple problema de expiracion corta.

---

## 3. Modelo de amenaza

Los escenarios de amenaza relevantes para ARHIAX son los siguientes.

### 3.1 Robo en transito

El token puede ser interceptado en trayecto por:

- degradacion de transporte
- configuraciones TLS debiles
- proxies o middleboxes comprometidos
- exposicion accidental en URLs, redirecciones o telemetria

### 3.2 Fuga en memoria, logs o trazas

El token puede filtrarse por:

- logs de debug
- serializacion de excepciones
- herramientas de observabilidad
- volcados de memoria
- respuestas de error que reflejan headers o payloads sensibles

### 3.3 Replay durante la ventana de validez

Un atacante puede reutilizar un token robado si:

- el token es bearer puro
- no existe validacion de `jti`
- la audiencia no se valida correctamente
- la ventana temporal es demasiado amplia
- el backend acepta multiples usos indistintos para la misma credencial

### 3.4 Movimiento lateral entre microservicios

Un servicio interno puede aceptar de forma excesivamente confiada un token que ya fue validado aguas arriba, permitiendo:

- reutilizacion en otra audiencia
- ampliacion indebida del alcance
- salto entre dominios funcionales
- transito de privilegio humano hacia contextos de servicio

### 3.5 Exfiltracion via agentes LLM

En arquitecturas de agentes, el riesgo diferencial es que el token:

- sea colocado en el prompt
- aparezca en memoria conversacional
- quede expuesto en la descripcion de tools
- sea reflejado por una respuesta de herramienta
- sea exfiltrado por prompt injection o manipulacion de salida

### 3.6 Deriva de autorizacion

El token puede ser formalmente valido y aun asi no deberia autorizar una accion si:

- el expediente no esta en estado permitido
- el predio o acto no corresponde al actor
- la operacion exige step-up auth
- la accion excede el nivel de autonomia permitido
- la solicitud no coincide con el caso o flujo vigente

---

## 4. Principios de diseno ARHIAX

La arquitectura objetivo se rige por los siguientes principios.

### 4.1 Zero-token-in-context

Ningun token operacional, refresh token, API key, cookie privilegiada, signed URL ni secreto equivalente puede aparecer en el contexto visible por el modelo.

### 4.2 Delegacion por accion, no por sesion amplia

Las credenciales deben emitirse para una accion, herramienta o recurso especifico, no para un espacio amplio de operacion reutilizable.

### 4.3 Proof-of-possession por defecto donde sea viable

La plataforma debe preferir mecanismos de posesion demostrable frente a bearer tokens reutilizables.

### 4.4 Validacion independiente en cada frontera de confianza

Cada servicio debe validar localmente la credencial antes de actuar. El gateway no es una raiz de confianza suficiente por si sola.

### 4.5 Autorizacion contextual ademas de validez criptografica

Que el token sea autentico y vigente no significa que la operacion deba ser permitida.

### 4.6 Fallo en cerrado

Si la verificacion, la politica, la consulta de revocacion o la prueba de posesion fallan o no pueden completarse, el resultado debe ser denegar.

### 4.7 Evidencia forense completa

Toda emision, uso, denegacion, revocacion y anomalia debe producir una huella correlacionable con actor, recurso, servicio y resultado.

---

## 5. Arquitectura objetivo

El patron de referencia recomendado para ARHIAX es el siguiente:

```text
Usuario o Servicio Llamador
  -> Identity Provider
  -> API Gateway
  -> Policy Layer
  -> Credential Broker
  -> Token Efimero de Proposito Unico
  -> Servicio o Herramienta Destino
  -> Plano de Evidencia y Monitoreo
```

La caracteristica estructural mas importante es la separacion entre:

- plano de contexto LLM
- plano de credenciales
- plano de autorizacion
- plano de evidencia

En ARHIA-DX, el modelo puede seleccionar una intencion de herramienta, pero no debe construir ni observar directamente la credencial utilizada para ejecutar dicha accion.

---

## 6. Componentes obligatorios

### 6.1 Identity Provider

El proveedor de identidad debe:

- autenticar identidades humanas y de workload
- emitir tokens firmados asimetricamente
- soportar exchange o delegacion de tokens
- rotar claves de firma de forma controlada
- permitir expiraciones cortas
- soportar refresh rotation con deteccion de reuse

Opciones recomendadas:

- Keycloak para control empresarial y soberania tecnica
- Auth0 cuando se priorice velocidad de despliegue y el contexto regulatorio lo permita

Requisitos minimos:

- `ES256` o `EdDSA`
- validacion estricta de `iss`
- `aud` especifica por servicio
- capacidad de DPoP donde aplique

### 6.2 API Gateway

El gateway debe aplicar controles de frontera:

- autenticacion inicial
- verificacion de firma y claims basicos
- validacion de tamano y forma minima del request
- controles anti-abuso y rate limiting
- rechazo temprano de payloads evidentemente maliciosos

No obstante, el gateway no reemplaza la validacion en el backend destino.

### 6.3 Credential Broker

El Credential Broker es la pieza central de la solucion ARHIAX.

Su funcion es desacoplar:

- autenticacion primaria
- decision de delegacion
- emision de credenciales efimeras
- inyeccion segura de credenciales en tool calls o microservicios

Responsabilidades del broker:

- recibir identidad ya autenticada
- verificar que existe base legal y tecnica para delegar
- emitir una credencial minima para una sola audiencia o accion
- ligar la credencial a posesion, tiempo, actor y contexto
- registrar evidencia de emision y uso
- soportar revocacion o invalidacion temprana

En una arquitectura ARHIAX madura, el broker reemplaza la necesidad de que el agente o el frontend porten tokens amplios de sesion para cada accion sensible.

### 6.4 Policy Layer

La capa de politicas decide si una accion valida debe ser autorizada en el contexto actual.

Debe evaluar:

- clasificacion de impacto de la operacion
- pertenencia del recurso al actor o a su ambito delegado
- estado del expediente o flujo
- limites por departamento, tenant o jurisdiccion
- restricciones por nivel de autonomia del agente
- requerimientos de aprobacion humana o step-up

Implementacion recomendada:

- OPA/Rego para evaluacion cercana al runtime
- Cedar como alternativa o complemento para modelado de autorizacion expresiva

### 6.5 Service Mesh e identidad de workload

La comunicacion interna debe apoyarse en:

- mTLS entre servicios
- identidad de workload verificable
- minimizacion del reenvio de tokens de usuario final

Patron recomendado:

- el token del usuario se valida en ingreso
- si un downstream necesita contexto del usuario, se usa token exchange o delegacion limitada
- si no necesita contexto del usuario, se utiliza identidad de servicio y contexto de negocio minimo

### 6.6 Plano de evidencia y monitoreo

Toda credencial efimera debe dejar huella en:

- emision
- validacion
- denegacion
- revocacion
- reutilizacion anomala
- fallo de posesion
- vinculacion con el recurso de negocio

Esto es especialmente importante en ARHIAX CM, donde el `jti` debe poder correlacionarse con el acto catastral, el expediente o el hash de transaccion correspondiente.

---

## 7. Estandar ARHIAX de diseno de tokens efimeros

Todo token efimero utilizado para acciones sensibles debe incluir, como minimo:

- `iss`
- `sub`
- `aud`
- `jti`
- `iat`
- `nbf` cuando la operacion lo requiera
- `exp`
- `scope` o claim equivalente de permiso granular
- `act` cuando exista delegacion
- `cnf` cuando se use posesion demostrable

Reglas de diseno:

- firma asimetrica obligatoria
- una sola audiencia por token cuando sea posible
- scopes de recurso y accion, no scopes amplios
- expiracion muy corta
- trazabilidad de emision asociada al objeto de negocio

Ejemplos de scopes adecuados:

- `catastro:read:predio:123`
- `catastro:update:acto:456`
- `tool:execute:consulta_radicado:case-987`
- `agent:invoke:evidence-store:append`

Ejemplos de scopes inadecuados:

- `catastro:*`
- `admin:all`
- `tool:*`

---

## 8. Estandar de transmision

Las credenciales efimeras deben transmitirse bajo las siguientes reglas.

### 8.1 Reglas generales

- nunca en query params
- nunca en fragments
- nunca en payloads visibles por el modelo
- nunca en logs de request
- nunca embebidas en respuestas de herramientas

### 8.2 Transporte externo

- TLS fuerte obligatorio
- HSTS
- DPoP cuando la clase de cliente lo soporte
- validacion estricta de origen y flujo

### 8.3 Transporte interno

- mTLS obligatorio en trafico sensible
- service identities verificables
- segmentacion de red y politicas de red deny-by-default

---

## 9. Estandar de validacion

Cada servicio debe validar localmente:

- algoritmo permitido
- firma
- `iss`
- `aud`
- `exp`
- `nbf` cuando aplique
- `jti`
- prueba de posesion si existe

Adicionalmente, debe ejecutar validaciones de negocio:

- correspondencia entre claims y payload
- autorizacion sobre el recurso
- estado valido del flujo
- cumplimiento de la politica de autonomia
- consistencia con tenant, departamento o jurisdiccion

La validacion debe ser fail-closed. Un error operativo no puede traducirse en permiso implicito.

---

## 10. Resistencia a replay

La mitigacion de replay en ARHIAX debe ser multicapa.

### 10.1 DPoP

DPoP reduce de forma sustantiva el valor de un token robado al vincularlo a una clave del cliente. No debe presentarse como eliminacion absoluta del replay, pero si como uno de los controles mas valiosos del stack externo.

### 10.2 mTLS-bound o identidad de workload

En trafico interno de alta confianza, la vinculacion a workload o canal autenticado reduce la reutilizacion indebida entre servicios.

### 10.3 `jti` y control de reutilizacion

El `jti` debe registrarse de modo que:

- pueda revocarse
- pueda detectarse su reuse
- pueda correlacionarse con anomalias de origen

### 10.4 Idempotency keys

Las operaciones de escritura sensibles deben soportar idempotency key para impedir reejecuciones ambiguas o repetidas por retransmision maliciosa.

### 10.5 Ventanas temporales cortas

Recomendacion ARHIAX:

- 30 a 60 segundos para tool calls de agentes
- 1 a 2 minutos para mutaciones de alto impacto
- hasta 5 minutos para lecturas sensibles

---

## 11. Modelo de revocacion

ARHIAX no debe depender de un modelo JWT puramente stateless para operaciones criticas.

Se recomienda un modelo hibrido:

- validacion local de firma y claims para baja latencia
- blacklist o cache de `jti` revocados en Redis con TTL igual a expiracion
- introspection o consulta al broker para operaciones de mayor sensibilidad
- refresh rotation con deteccion de reutilizacion en sesiones humanas

Este compromiso introduce estado operativo, pero eleva drásticamente la capacidad de control, respuesta e investigacion.

---

## 12. Patron especifico ARHIA-DX para agentes

### 12.1 Regla fundamental

El agente razona sobre intenciones y resultados de negocio, no sobre credenciales.

### 12.2 Patron seguro de tool call

1. el modelo selecciona la tool por intencion
2. el orquestador valida parametros, politica y contexto
3. el adaptador solicita al Credential Broker una credencial efimera minima
4. el token se inyecta solo en runtime hacia la herramienta o servicio
5. la respuesta vuelve saneada al modelo

### 12.3 Patron inseguro

No se permite:

- colocar tokens en el prompt
- poner headers de autorizacion en campos visibles para el modelo
- permitir que el modelo construya requests arbitrarios con credenciales crudas
- devolver al modelo responses que contengan cookies, signed URLs o metadata sensible

### 12.4 Saneamiento de salida

Los adaptadores deben eliminar:

- headers de autorizacion
- cookies
- secretos derivados
- trazas con material sensible
- mensajes de error que reflejen credenciales

---

## 13. Autorizacion contextual para ARHIAX CM

En operaciones catastrales y equivalentes, la decision no debe depender solo del token. Debe evaluarse:

- si la identidad tiene derecho sobre el predio, expediente o acto
- si el acto esta permitido en ese estado del flujo
- si la operacion supera umbrales de impacto
- si requiere step-up auth
- si requiere confirmacion transaccional
- si requiere aprobacion dual
- si la solicitud es congruente con la jurisdiccion o ambito funcional correspondiente

Para actos de alto impacto se recomienda:

- step-up auth
- explicit confirmation
- dual approval segun politica
- idempotency enforcement
- correlacion entre `jti` y hash del acto

---

## 14. Observabilidad y deteccion

Nunca debe loggearse el token completo.

Campos observables permitidos:

- `jti`
- `sub`
- `act`
- `aud`
- clase de token
- bucket de TTL
- IP o workload identity
- resultado de validacion
- identificador del recurso de negocio

Alertas recomendadas:

- mismo `jti` usado desde dos origenes
- uso posterior a `exp`
- `aud` mismatch repetido
- fallo de prueba de posesion
- volumen anomalo de emision para un mismo actor
- rafaga de denegaciones de alto riesgo seguida de reintentos

---

## 15. Stack tecnologico recomendado

### Emision e identidad

- Keycloak o Auth0

### Prueba de posesion

- DPoP para clientes compatibles

### Seguridad interna

- Istio o Envoy con mTLS

### Delegacion y credenciales

- Credential Broker dedicado de ARHIAX

### Politica y autorizacion

- OPA/Rego y, donde aporte valor, Cedar

### Secretos

- HashiCorp Vault con leases cortos y rotacion

### Revocacion

- Redis con TTL alineado al `exp`

### Monitoreo

- SIEM corporativo con reglas de anomalia de `jti`, `aud`, posesion y reuse

---

## 16. Hoja de ruta de implementacion

### Fase 1. Endurecimiento inmediato

- forzar firma asimetrica
- validar `iss`, `aud`, `exp`, `nbf`, `jti` y algoritmo en cada servicio
- eliminar secretos de prompts, logs, query strings y errores serializados
- reducir TTL
- introducir revocacion basica y alertas minimas

### Fase 2. Refuerzo de fronteras de confianza

- desplegar mTLS
- adoptar DPoP en clientes soportados
- separar identidades humanas, de agente y de servicio
- refinar scopes por accion y recurso

### Fase 3. Modelo ARHIAX de delegacion

- desplegar Credential Broker
- migrar tool calls a credenciales por accion
- institucionalizar zero-token-in-context
- agregar sanitizacion de salidas de tools

### Fase 4. Alta aseguracion

- incorporar step-up auth
- dual approval para actos criticos
- union fuerte entre token, transaccion y estado del flujo
- ejercicios de red team sobre replay, lateral movement y prompt injection

---

## 17. Requisitos no negociables

Los siguientes puntos deben considerarse obligatorios en el estado objetivo:

- no confiar en bearer tokens puros para acciones criticas
- no exponer tokens a contexto visible por LLM
- no depender solo del gateway para validar
- no usar scopes amplios para acciones catastrales
- no loggear tokens crudos ni headers sensibles en produccion

---

## 18. Conclusion ejecutiva

La solucion ARHIAX de mayor madurez frente al riesgo de tokens efimeros no es un JWT ligeramente mas corto o una validacion adicional aislada. Es una arquitectura de delegacion gobernada en la que cada credencial es de vida corta, de proposito acotado, ligada al poseedor cuando sea posible, validada en cada frontera, autorizada segun contexto de negocio, aislada del plano LLM y trazable de extremo a extremo.

Esa es la postura que mejor equilibra seguridad, auditabilidad, resiliencia operativa y adopcion empresarial para ARHIAX CM, ARHIA-DX y AgentCreator.

# Justificación Técnica del Esquema de Datos de Auditoría Académica

## 1. Resumen Ejecutivo y Alcance

El presente documento expone los fundamentos de diseño y la justificación técnica del esquema de datos estructurado adoptado para el registro de auditoría académica en el sistema de calificaciones. El objetivo central de la arquitectura es proporcionar un registro transaccional inmutable, auditable y criptográficamente verificable que documente cada evento de registro y modificación de notas sin comprometer datos personales sensibles (PII).

La especificación adopta una estructura jerárquica con cabecera de metadatos de lote (`metadata`) y un cuerpo de eventos polimórficos (`events`), serializados bajo estándares de JSON canónico determinista y validados mediante esquemas de resumen criptográfico (SHA-256).

---

## 2. Atributos de Calidad de Seguridad

El esquema ha sido concebido bajo los pilares fundamentales de la seguridad de la información aplicados a sistemas de auditoría forense:

### 2.1 Confidencialidad y Minimización de Datos (Zero-PII)
- **Pseudonimización Estricta:** Se eliminan por completo los identificadores civiles (nombres, cédulas, códigos de matrícula estudiantil expuestos). Todos los actores (estudiantes, docentes, coordinadores) y recursos (materias, eventos) se representan mediante identificadores opacos y pseudoaleatorios generados con `crypto/rand` y formato RFC 4122 (UUIDv4).
- **Segmentación Semántica por Prefijo:** Para garantizar legibilidad estructural en auditoría sin filtrar identidad, se emplean prefijos estandarizados:
  - `STU-<uuid>` para estudiantes.
  - `DOC-<uuid>` para docentes y evaluadores.
  - `SUB-<uuid>` para materias o cursos académicos.
  - `EVT-<uuid>` para eventos individuales.
- **Cumplimiento Normativo:** Satisface el principio de minimización de datos exigido por marcos regulatorios modernos (GDPR, Habeas Data, ISO/IEC 27001), mitigando riesgos ante fugas o accesos no autorizados al repositorio de logs.

### 2.2 Integridad Criptográfica Multinivel
- **Integridad Atómica (Payload Hash):** Cada evento individual en el array `events` incorpora un campo `payload_hash` derivado del digest SHA-256 del contenido canónico de su transacción. Esto asegura que ninguna nota, motivo, evaluador o timestamp individual pueda ser alterado retroactivamente sin invalidar la firma del evento.
- **Integridad de Lote (Batch Hash):** La serialización determinista permite tratar el archivo completo de log como un bloque inmutable cuyo hash raíz garantiza la integridad total de la colección de eventos y sus metadatos.
- **Detección Inmediata de Manipulación (Tamper-Evidence):** Cualquier modificación accidental o maliciosa (inyección de eventos espurios, alteración de calificaciones o reordenamiento) rompe la coincidencia de hashes tanto a nivel de registro como de lote.

### 2.3 Trazabilidad y Principio de No Repudio
- **Atribución Inequívoca:** Cada acción queda vinculada a un actor específico (`evaluator_uid` en registros, `modifier_uid` en modificaciones) con su respectivo rol de autorización (`DOCENTE`, `COORDINADOR`, `ADMIN_SISTEMA`).
- **Monotonía Temporal en UTC:** Todas las marcas de tiempo (`timestamp`, `created_at`) se estandarizan a tiempo universal coordinado en formato RFC 3339 (`2006-01-02T15:04:05Z07:00`), eliminando ambigüedades derivadas de zonas horarias locales o cambios estacionales.
- **Inmutabilidad Transaccional:** El diseño del flujo prohíbe la sobreescritura destructiva de datos. Los cambios se registran exclusivamente como eventos adicionales de modificación encadenados temporalmente.

---

## 3. Justificación del Esquema

### 3.1 Separación Estructural: `metadata` vs. `events`

La división entre una cabecera administrativa (`metadata`) y el vector secuencial de transacciones (`events`) responde a principios de arquitectura de software y procesamiento de flujos:

1. **Contexto Operacional Aislado:**
   - La cabecera encapsula variables de control operacional: `log_id`, `schema_version`, `created_at`, `total_events` y `environment`.
   - Permite clasificar el entorno de ejecución (`AUDIT_SIMULATION`, `STAGING`, `PRODUCTION`) y validar la compatibilidad de esquemas antes de parsear cargas masivas de datos.
2. **Validación Rápida de Truncamiento:**
   - El atributo `total_events` actúa como suma de comprobación cardinal. Si un archivo sufre truncamiento por interrupción de I/O o transferencia de red incompleta, el validador rechaza el log inmediatamente (`total_events != len(events)`) sin requerir comprobaciones criptográficas costosas en primera instancia.
3. **Optimización de Indexación y Auditoría:**
   - Motores de ingesta de logs y herramientas SIEM pueden indexar la cabecera sin necesidad de procesar los miles de eventos hijos, acelerando búsquedas temporales y conciliaciones batch.

### 3.2 JSON Canónico frente a Formatos Binarios Propietarios

Para escenarios de auditoría forense y custodia digital a largo plazo, la elección de JSON Canónico determinista frente a formatos binarios (Protocol Buffers, Avro, BSON) se fundamenta en los siguientes criterios técnicos:

| Criterio | JSON Canónico (Deterministic JSON) | Formatos Binarios Propietarios |
| :--- | :--- | :--- |
| **Transparencia Forense** | Inspeccionable y validable sin herramientas especializadas (humano-legible). | Requiere esquemas externos (`.proto`, `.avsc`) y compiladores específicos. |
| **Preservación a Largo Plazo** | Estándar abierto universal (RFC 8259 / RFC 8785); independiente de plataformas. | Susceptible a obsolescencia de versiones de librerías y pérdida de esquemas. |
| **Reproducibilidad Criptográfica** | Orden alfabético estricto de claves y supresión de escape HTML garantizan identidad byte a byte. | Serializadores binarios suelen generar variaciones de alineación o campos no definidos. |
| **Portabilidad Multi-Lenguaje** | Cualquier lenguaje estándar valida y procesa el contenido nativamente. | Requiere dependencias externas y bindings propietarios por lenguaje. |

La implementación en Go utiliza `json.NewEncoder` con `SetEscapeHTML(false)` e indentación controlada de dos espacios, impidiendo que secuencias legítimas como `<`, `>` o `&` en descripciones académicas muten a secuencias Unicode escapadas (`\u003c`, etc.), preservando la fidelidad exacta del hash SHA-256.

---

## 4. Auditoría y Trazabilidad de Calificaciones: Transición de Estados

### 4.1 Justificación de `previous_grade` y `new_grade` en `MODIFICACION_NOTA`

El modelado del evento `MODIFICACION_NOTA` exige registrar explícitamente tanto la calificación anterior (`previous_grade`) como la calificación actualizada (`new_grade`), junto con una razón documentada (`reason >= 10` caracteres). Esta decisión de diseño obedece a requerimientos forenses críticos:

1. **Reconstrucción Inmediata del Delta Transaccional:**
   - Permite al auditor evaluar el impacto exacto de la modificación (magnitud y sentido del ajuste) de manera aislada, sin necesidad de reconstruir todo el historial de eventos previos del estudiante.
2. **Validación de Consistencia y Precondición de Estado:**
   - Actúa como una validación de concurrencia optimista (*compare-and-swap*). Si el `previous_grade` registrado no coincide con el valor de la última nota en base de datos, el auditor identifica una inconsistencia temporal o intento de evasión de eventos intermedios.
3. **Prevención de Modificaciones Nulas o Inadvertidas:**
   - Se impone una regla de dominio estricta: `|new_grade - previous_grade| >= 0.01`. Esto previene registros basura o ejecuciones redundantes de scripts docentes.
4. **Exigencia de Causalidad Documentada:**
   - La inclusión de un campo `reason` obligatorio (con restricción de longitud mínima) asegura que todo cambio de calificación cuente con respaldo administrativo (revisión de examen, sustentación extemporánea, corrección de digitación), consolidando la cadena de custodia y rendición de cuentas.

---

## 5. Tabla Resumen para Sustentación (Slides / Cheat Sheet)

| Dimensión | Decisión Técnica | Beneficio Operacional / Auditoría |
| :--- | :--- | :--- |
| **Identidad** | UIDs prefijados opacos (`STU-`, `DOC-`, `SUB-`) | Cumplimiento Zero-PII, anonimización irreversible ante terceros. |
| **Integridad** | Hashes duales (SHA-256 en payloads + hash de lote) | Tamper-evidence a nivel de registro atómico y lote consolidado. |
| **Serialización**| Determinista con 2 espacios y `SetEscapeHTML(false)` | Hashes idénticos byte a byte entre ejecuciones distribuidas. |
| **Estructura** | Separación `metadata` / `events` | Validación pre-vuelo (conteo y versión) e indexación acelerada. |
| **Auditoría Notas**| Registro de `previous_grade`, `new_grade` y `reason` | Trazabilidad del delta, verificación de precondiciones y no repudio. |
| **Tiempo** | Marcas UTC bajo estándar RFC 3339 | Monotonía temporal inequívoca y auditoría forense cronológica. |

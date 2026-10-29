# Guion Técnico y Pauta de Grabación para Video de Sustentación Grupal
## Proyecto: Protección de Logs Estructurados en Reposo (Taller 2 – Criptografía)

> **Documento de Coordinación y Guion de Grabación (Entregable 3)**  
> **Duración estimada:** 10 – 12 minutos  
> **Plataforma sugerida de grabación:** Zoom / Google Meet / OBS Studio (grabación multipantalla con cámaras encendidas para los 4 integrantes).  
> **Requisito formal de evaluación:** Intervención activa y visible de la totalidad de los miembros del equipo.

---

## 👥 Asignación de Roles y Tiempos de Intervención

| Rol / Miembro | Responsabilidad Temática | Slides Asociadas | Tiempo Estimado |
| :--- | :--- | :--- | :---: |
| **Dev 1: Dominio & Generación** | Apertura, contexto de negocio, modelado de eventos, UIDs y notas uniformes. | Slides 1, 2, 4 | 02:30 min |
| **Dev 2: Hashing & Integridad** | Prevención de circularidad en payload, SHA-256, streaming O(1) y `crypto/subtle`. | Slides 3, 5, 6, 10 | 02:30 min |
| **Dev 3: Cifrado & Secretos** | AES-256-GCM nativo, AEAD, Tag GMAC, gestión de llaves y almacenamiento desacoplado. | Slides 7, 8, 9 | 02:30 min |
| **Dev 4: CLI, Demo & Cierre** | Orquestación end-to-end, demo en vivo en terminal, prueba de tampering, IA y cierre. | Slides 11, 12, 13, 14 | 03:30 min |

---

## 🎬 Guion Detallado Escena por Escena

### Bloque 1: Apertura, Contexto y Modelado de Datos (00:00 – 02:30)
**Voz y Cámara:** **Dev 1 (Dominio y Generación)**  
**En Pantalla:** Diapositivas 1 (Portada), 2 (Contexto) y 4 (Esquema JSON).

- **[00:00 - 00:30] Introducción Institucional:**
  > *"Cordial saludo profesor y evaluadores. Somos el grupo conformado por [Nombre 1], [Nombre 2], [Nombre 3] y [Nombre 4], y presentamos la sustentación del Taller 2 de Criptografía: Protección de Logs Estructurados en Reposo. La totalidad del proyecto fue desarrollado en Go utilizando de forma exclusiva bibliotecas nativas y estándar para la capa criptográfica."*

- **[00:30 - 01:15] Planteamiento del Problema (Slide 2):**
  > *"En el entorno de gestión académica universitaria, los registros y modificaciones de calificaciones representan operaciones de alto impacto sensible. Si un log reposa en texto plano en el disco de un servidor, cualquier usuario con privilegios locales o un atacante que vulnere el sistema de archivos podría alterar una nota o exfiltrar datos privados. Nuestro objetivo fue blindar este ciclo de almacenamiento garantizando tres atributos esenciales: confidencialidad, integridad granular por registro e integridad global del archivo."*

- **[01:15 - 02:30] Modelado de Eventos y Distribución de Notas (Slide 4):**
  > *"Para modelar el dominio (Paso 2), diseñamos un esquema JSON estructurado con dos clases de eventos: `REGISTRO_NOTA` y `MODIFICACION_NOTA`. Aplicamos el principio de opacidad mediante identificadores sintéticos con prefijos claros: `USR-STU-` para estudiantes, `USR-DOC-` para docentes evaluadores y `SUB-` para asignaturas.*  
  > *La calificación se genera estocásticamente con una distribución uniforme rigurosa en el intervalo de 0.0 a 5.0 mediante el paquete `math/rand/v2`. En los eventos de modificación, incorporamos tanto la calificación anterior (`previous_grade`) como la nueva (`new_grade`) junto a una justificación administrativa obligatoria, garantizando trazabilidad y no repudio. Le doy la palabra a mi compañero [Dev 2], quien explicará cómo protegemos la integridad de estos datos sin caer en circularidad criptográfica."*

---

### Bloque 2: Hashing, Prevención de Circularidad y Auditoría (02:30 – 05:00)
**Voz y Cámara:** **Dev 2 (Hashing e Integridad)**  
**En Pantalla:** Diapositivas 3 (Atributos), 5 (Circularidad), 6 (SHA-256) y 10 (Auditoría Forense).

- **[02:30 - 03:30] La Solución al Problema de Circularidad (Slide 5):**
  > *"Gracias [Dev 1]. Uno de los desafíos técnicos más importantes del taller reside en el Paso 3: ¿cómo incorporar el hash de un registro dentro del mismo registro sin que el cálculo se vuelva circular e infinito? Si intentamos hashear el evento completo incluyendo el campo `payload_hash`, el valor muta al inyectar el digest.*  
  > *Nuestra solución arquitectónica fue desacoplar estrictamente el evento en dos capas: el contenedor exterior y el sub-objeto interno `payload`. El hash SHA-256 se computa exclusivamente sobre la representación canónica en bytes del `payload`. Luego, ese digest resultante se asigna al campo `payload_hash` del contenedor. De esta forma, el payload queda sellado e inmutable, y la verificación posterior se realiza recalculando el hash del payload y contrastándolo directamente."*

- **[03:30 - 04:15] SHA-256 Nativo y Streaming O(1) (Slide 6):**
  > *"Para todos los resúmenes criptográficos implementamos SHA-256 bajo el estándar NIST FIPS 180-4 mediante el paquete nativo `crypto/sha256`. Para los hashes globales de los archivos (Pasos 5, 7 y 9), implementamos un patrón de lectura por streaming con `io.Copy`, lo que garantiza una complejidad espacial de memoria O(1). Esto protege al sistema contra ataques de denegación de servicio por memoria agotada ante archivos masivos.*  
  > *Además, los testigos `.sha256` se almacenan en formato estándar GNU Coreutils, permitiendo interoperabilidad forense directa con el comando del sistema operativo `sha256sum -c`."*

- **[04:15 - 05:00] Mitigación de Timing Attacks (Slide 10):**
  > *"En el Paso 10, realizamos una doble auditoría: global registro contra descifrado y granular campo por campo. Para evitar ataques de canal lateral o 'Timing Attacks' —donde un atacante deduce bytes correctos midiendo los nanosegundos que tarda la comparación en fallar— utilizamos estrictamente `crypto/subtle.ConstantTimeCompare`. A continuación, mi compañero [Dev 3] explicará la capa de cifrado y el ciclo de vida de llaves."*

---

### Bloque 3: Cifrado en Reposo, AEAD y Gestión de Secretos (05:00 – 07:30)
**Voz y Cámara:** **Dev 3 (Cifrado y Secretos)**  
**En Pantalla:** Diapositivas 7 (AES-256-GCM), 8 (Diagrama Estructural) y 9 (Diagrama de Comportamiento).

- **[05:00 - 06:00] Cifrado Autenticado AES-256-GCM (Slide 7):**
  > *"Muchas gracias [Dev 2]. Para la confidencialidad en reposo (Paso 6), seleccionamos AES-256 en modo GCM (Galois/Counter Mode), conforme a la recomendación NIST SP 800-38D. Elegimos GCM porque es un esquema AEAD: no solo cifra la información mediante contadores, sino que genera simultáneamente un Authentication Tag (GMAC) de 128 bits.*  
  > *Esto erradica los ataques de manipulación de bits ('bit-flipping'): si un atacante altera un solo byte del archivo cifrado en disco, la función de descifrado rechaza la operación automáticamente antes de escribir un solo byte descifrado."*

- **[06:00 - 06:45] Ciclo de Vida de Llaves y Desacoplamiento (Slide 7 y 8):**
  > *"Siguiendo las directrices del NIST SP 800-57, la clave simétrica de 256 bits y el nonce de 96 bits se generan utilizando exclusivamente `crypto/rand`, alimentado por la entropía del kernel del sistema operativo. Cada ejecución del pipeline produce una clave y un nonce frescos.*  
  > *Cumpliendo el principio de separación de privilegios, el archivo cifrado `academic_log.enc` y los insumos criptográficos `crypto_metadata.json` se almacenan en artefactos desacoplados físicamente con permisos de archivo restringidos (`0600`), garantizando que la tenencia del ciphertext no comprometa los datos sin los secretos asociados."*

- **[06:45 - 07:30] Reconstrucción Fiel y Arquitectura (Slide 8 y 9):**
  > *"En los Pasos 8 y 9, el pipeline recupera el log mediante descifrado autenticado hacia `academic_log_decrypted.json` y computa su hash correspondiente. Como se aprecia en nuestros diagramas estructural y de comportamiento (Slides 8 y 9), la arquitectura aísla el dominio de los adaptadores de almacenamiento y criptografía. Doy paso a mi compañero [Dev 4] para la demostración práctica en vivo por terminal."*

---

### Bloque 4: Demostración Práctica, Uso de IA y Conclusiones (07:30 – 11:00)
**Voz y Cámara:** **Dev 4 (CLI, Integración y Demo)**  
**En Pantalla:** Terminal interactiva en vivo, Diapositiva 11 (Resultados), Diapositiva 12 (Tampering), Diapositiva 13 (Declaración IA) y Diapositiva 14 (Conclusiones).

- **[07:30 - 08:30] Demostración en Terminal (Modo Flujo Completo):**
  > *"Gracias [Dev 3]. Procedo a compartir mi terminal para evidenciar el funcionamiento en tiempo real de nuestra aplicación CLI, desarrollada con la librería `survey/v2`."*  
  *(Dev 4 ejecuta en la terminal)*:
  ```bash
  go run ./cmd/cli --auto -n 25
  ```
  > *"Observen cómo la consola imprime la trazabilidad secuencial explicable de los 10 pasos: desde la configuración del volumen, la inyección del hash sin circularidad, el cifrado AES-256-GCM, hasta la recuperación y auditoría forense.*  
  > *En pantalla se despliega la tabla comparativa de hashes SHA-256. Noten que el Hash del Log Original (P5) y el Hash del Log Descifrado (P9) son idénticos al 100%, mientras que el Hash del Log Cifrado (P7) es completamente divergente por la entropía del cifrado. El veredicto final se resalta en verde con el badge de verificación exitosa."*

- **[08:30 - 09:30] Demostración de Resistencia Forense (Prueba de Tampering):**
  > *"Ahora demostraremos la robustez del sistema simulando un ataque de adulteración deliberada en disco. Alteraremos directamente una calificación en el archivo descifrado mediante `sed`:"*  
  *(Dev 4 ejecuta en consola)*:
  ```bash
  sed -i 's/"grade": [0-9.]*/"grade": 0.0/' output/academic_log_decrypted.json
  ```
  *(Dev 4 abre el menú y ejecuta la Opción 6 de Auditoría)*:
  > *"Al ejecutar el auditor (Paso 10), el sistema detecta de inmediato la discrepancia: la comparación matemática falla y la verificación registro a registro identifica el evento específico alterado. El veredicto cambia contundentemente a rojo: `[ ✘ ] ALERTA DE SEGURIDAD: VIOLACIÓN DE INTEGRIDAD O CORRUPCIÓN`."*

- **[09:30 - 10:15] Declaración Obligatoria de Uso Responsable de IA (Slide 13):**
  > *(Dev 4 regresa a la presentación - Slide 13)*:  
  > *"En cumplimiento de las normas éticas del curso, declaramos de forma transparente el uso responsable de herramientas de Inteligencia Artificial (Claude Code y Google Gemini/Antigravity). Estas herramientas se utilizaron exclusivamente como asistentes de 'Pair Programming' para la estructuración de pruebas unitarias basadas en tablas y sugerencias de diseño idiomático en Go.*  
  > *La totalidad de la lógica criptográfica, la selección de algoritmos nativos, la resolución matemática de la circularidad y la validación de código fueron realizadas, revisadas y comprobadas rigurosamente por los integrantes humanos mediante una suite de más de 30 pruebas unitarias con 100% de éxito."*

- **[10:15 - 11:00] Conclusiones y Cierre Grupal:**
  > *(Los 4 integrantes encienden micrófono)*:  
  > *"Como conclusión, hemos demostrado que es posible asegurar la cadena de custodia y la confidencialidad de datos en reposo aplicando estándares de la industria como AES-256-GCM y SHA-256, sin dependencias externas y con alto rendimiento.*  
  > *Muchas gracias por su atención."*

---

## 🛠️ Checklist Técnico Previo a la Grabación

- [ ] Verificar que `go test ./...` pase en verde al 100%.
- [ ] Limpiar la carpeta `output/` antes de comenzar la grabación (`rm -rf output/*`).
- [ ] Ajustar la resolución de terminal a un tamaño de fuente legible (ej. 16px o 18px con contraste oscuro).
- [ ] Tener listos los comandos en un bloc de notas o terminal secundaria para evitar demoras de tipeo.
- [ ] Probar audio y nivel de ganancia de micrófono de cada uno de los 4 integrantes.
- [ ] Exportar las diapositivas a `.PDF` y tenerlas abiertas en modo pantalla completa.

# Declaración de Autoría y Uso Responsable de Inteligencia Artificial Generativa

**Institución:** Universidad del Valle  
**Facultad:** Facultad de Ingeniería  
**Escuela:** Escuela de Ingeniería de Sistemas y Computación  
**Asignatura:** Criptografía y Seguridad en Redes  
**Proyecto:** Taller 2 — Protección Criptográfica de Logs Estructurados en Reposo  
**Lenguaje y Plataforma:** Go 1.22+ (Zero CGO • 100% Go Standard Library)  

---

## 1. Compromiso Ético y Declaración de Integridad

En estricto cumplimiento de las directrices académicas de la Universidad del Valle, los estatutos de integridad estudiantil y los principios éticos que rigen la práctica profesional de la ingeniería de sistemas y la ciberseguridad, los integrantes del equipo declaramos de manera explícita y transparente que para el diseño, desarrollo, verificación y documentación de la herramienta de línea de comandos (CLI) objeto de este taller, se contó con la asistencia de sistemas de Inteligencia Artificial Generativa:

* **Google Antigravity CLI:** Entorno de asistencia técnica y pair programming impulsado por modelos avanzados de razonamiento (*Gemini 3.8 Flash/Argon 4*).
* **Anthropic Claude Code:** Herramienta de asistencia por terminal y análisis de código (*Claude 3.7 Sonnet*).
* **AgentBuff Presentation Skills:** Se realizaron las diapositivas con ayuda de la skill [https://github.com/nugrahalabib/AgentBuff-Presentation-Skills](https://github.com/nugrahalabib/AgentBuff-Presentation-Skills).

Dicha asistencia operó en todo momento bajo un marco riguroso de **supervisión humana continua**, **auditoría manual de seguridad** y **verificación empírica basada en pruebas automatizadas**. En ningún caso las herramientas de IA actuaron de manera autónoma o con delegación de criterio de ingeniería.

---

## 2. Alcance Metodológico y Áreas de Asistencia

La interacción con los modelos de IA se delimitó metodológicamente a cuatro áreas técnicas específicas:

### 2.1 Planificación, Gestión Ágil y Modelado de Amenazas
* **Descomposición Funcional:** Apoyo en la subdivisión de los diez requerimientos funcionales del taller en historias de usuario atómicas (historias `US-1` a `US-11`), definiendo criterios de aceptación verificables y dependencias secuenciales que fueron gestionadas en la plataforma **ClickUp**.
* **Estructuración de Sprints:** Organización metodológica del plan de trabajo en tres fases operativas (Fase 1: CLI nativa y mitigación de circularidad; Fase 2: Pipeline de datos sintéticos y serialización determinista; Fase 3: Primitivas criptográficas simétricas, auditoría forense y empaquetado).
* **Modelado de Amenazas (STRIDE):** Asistencia en la formulación de la matriz de riesgos contra datos en reposo, identificando vectores de manipulación interna (*tampering* de calificaciones), exfiltración no autorizada de datos personales (*information disclosure*) y ataques de canal lateral basados en microsegundos (*timing attacks*).

### 2.2 Ingeniería de Software, Arquitectura CLI y Procesamiento de Flujos
* **Arquitectura de Dominio Desacoplada:** Asistencia en la estructuración idiomática del código Go siguiendo principios de Clean Architecture, segregando las interfaces de dominio (`domain/`), la orquestación del pipeline (`pipeline/`), los adaptadores de infraestructura criptográfica (`crypto/`) y la capa de interacción de usuario (`cli/`).
* **CLI Robusta y Parseo Estándar:** Implementación de banderas nativas por línea de comandos (`--auto`, `-n`, `--dry-run`, `-o`, `--config`) utilizando exclusivamente el paquete estándar `flag.FlagSet`, garantizando compatibilidad POSIX y códigos de salida deterministas (`0` para éxito, `1` para violación de integridad o tampering, `2` para error de sintaxis o E/S).
* **Procesamiento de Archivos por Streaming O(1):** Diseño de patrones de lectura y cómputo de resúmenes criptográficos por bloques mediante `io.Copy` conectado a `crypto/sha256`. Esto permite procesar volúmenes masivos de registros o archivos de gran tamaño con una complejidad espacial de memoria constante `O(1)` (buffer fijo de 32 KB), eliminando vulnerabilidades de denegación de servicio (DoS) por agotamiento de RAM o activación del *OOM Killer* del kernel de Linux.

### 2.3 Primitivas Criptográficas y Mitigación de Circularidad
* **Resolución de la Circularidad de Hashing:** Co-diseño del mecanismo de desacoplamiento de dos niveles para resolver la paradoja de autorreferencia en el sellado del evento:
  $$\text{PayloadHash} = \text{SHA-256}(\text{CanonicalJSON}(\text{Event}.\text{Payload}))$$
  Se aisló el contenedor mutable exterior del sub-objeto interno inmutable `payload`, aplicando serialización canónica determinista bajo el estándar **RFC 8785** para garantizar que la inyección del digest `payload_hash` no altere los bytes que le dieron origen.
* **Cifrado Simétrico Autenticado (AEAD):** Implementación de **AES-256-GCM** bajo las recomendaciones NIST SP 800-38D, utilizando claves de 256 bits generadas con entropía criptográfica (`crypto/rand`), vectores de inicialización (nonces) únicos de 96 bits generados dinámicamente por ejecución (garantía de cero reuso de nonce) y etiquetas de autenticación Galois (GMAC) de 128 bits.
* **Higiene contra Canales Laterales:** Implementación obligatoria de `crypto/subtle.ConstantTimeCompare` en la auditoría forense del Paso 10, asegurando que la comparación bit a bit de hashes tome un tiempo invariable independiente de la posición del primer byte divergente, neutralizando ataques de temporización (*timing attacks*).

### 2.4 Generación de Matrices de Pruebas y Validación Empírica
* **Table-Driven Tests:** Generación asistida de matrices de casos de prueba estructuradas idiomáticamente en Go, cubriendo casos nominales, valores límite en calificaciones estocásticas (`0.0` y `5.0`), entradas malformadas, archivos truncados y llaves corruptas.
* **Pruebas de Tampering:** Estructuración de scripts de mutación deliberada de bytes (*bit-flipping*) en el archivo cifrado para comprobar empíricamente que el tag GMAC aborta el descifrado (`cipher: message authentication failed`), así como pruebas de manipulación quirúrgica de notas en texto claro para verificar la alarma forense en la auditoría registro a registro.

---

## 3. Protocolo de Supervisión Humana, Validación y Auditoría

La incorporación de cualquier sugerencia o fragmento de código derivado de la interacción con los modelos de IA estuvo sujeta a tres filtros obligatorios de gobernanza humana:

1. **Revisión Manual Línea por Línea (Zero Blind Trust):**  
   Ninguna línea de código generada por IA fue integrada de manera directa al repositorio sin una lectura crítica previa, comprendiendo su propósito, flujo de ejecución y manejo de errores. Se descartaron sugerencias que promovían el uso de paquetes de terceros o patrones no idiomáticos.
2. **Mandato Estricto de Cero Dependencias Criptográficas Externas (Zero CGO):**  
   Frente a sugerencias del modelo que proponían librerías externas o wrappers CGO para criptografía, el equipo impuso el criterio estricto de basarse 100% en la biblioteca estándar de Go (`crypto/aes`, `crypto/cipher`, `crypto/sha256`, `crypto/rand`, `crypto/subtle`). Esta decisión previene ataques de envenenamiento de dependencias en la cadena de suministro de software (*software supply chain attacks*) y asegura binarios estáticos reproducibles.
3. **Auditoría por Pares mediante Pull Requests:**  
   Todo cambio fue gestionado a través de ramas independientes y Pull Requests en Git, requiriendo revisión y aprobación obligatoria entre los miembros del equipo antes del merge a la rama principal (`main`).
4. **Validación Automatizada y Detección de Concurrencia:**  
   El software fue sometido a la suite de pruebas completa ejecutada con el detector de condiciones de carrera:
   ```bash
   go test -v -race -cover ./...
   ```
   Alcanzando un **100% de cobertura** en la capa de CLI (`./cmd/cli/...`) y módulos internos (`./internal/...`), garantizando la ausencia de condiciones de carrera (*race conditions*) y fugas de memoria.

---

## 4. Dominio Técnico y Declaración de Autoría Plena

Los integrantes del equipo declaramos de manera unánime:

1. Que poseemos un entendimiento profundo, completo e integral del código fuente entregado, de su arquitectura por capas, de las estructuras de datos, de la gestión de memoria por streaming y de los principios matemáticos y criptográficos que sustentan cada algoritmo implementado.
2. Que estamos en plena capacidad de explicar, justificar, depurar y defender técnicamente cualquier función, estructura, bandera de terminal o decisión de diseño presente en la solución.
3. Que asumimos la **autoría intelectual plena, la responsabilidad técnica, ética y académica sobre el 100% de los artefactos, documentación y código entregados** en este taller.

---

### Integrantes y Firmas de Responsabilidad:

| Nombre del Estudiante | Código Estudiantil | Rol Técnico Principal en el Proyecto |
| :--- | :---: | :--- |
| **Jose Antonio Castelblanco** | *[Código]* | Modelado de Dominio & Generador Estocástico |
| **Braulio Robledo** | *[Código]* | Integridad, Hashing SHA-256 & Auditoría Dual |
| **Steven Nieves** | *[Código]* | Cifrado AES-256-GCM & Gestión de Secretos |
| **Juan José Bolaños** | *[Código]* | Orquestación Pipeline, CLI & Tampering Tests |

**Fecha de Declaración:** 3 de Noviembre de 2026  
**Lugar:** Santiago de Cali, Colombia — Universidad del Valle

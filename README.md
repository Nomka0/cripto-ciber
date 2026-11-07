# Taller Dos – Criptografía
## PROTECCIÓN DE LOGS ESTRUCTURADOS EN REPOSO

### Introducción
En un sistema de gestión académica universitaria, el proceso de registro de notas y modificación de notas constituye una operación sensible desde la perspectiva de ciberseguridad e ingeniería de software. Una posible vulneración de estos eventos afecta la confianza en la información académica y, por tanto, requieren mecanismos que fortalezcan la trazabilidad, la integridad y la confidencialidad de los datos.

En este taller se trabajará con la noción de **datos en reposo**, centrándose en la generación y protección de un archivo simulado de logs estructurados que representa operaciones académicas sensibles. El propósito es diseñar e implementar un módulo que permita demostrar, mediante mecanismos criptográficos, que:

* El log generado puede protegerse frente a lectura no autorizada.
* Cualquier alteración del contenido puede ser detectada.
* El proceso de cifrado y descifrado preserva la información original.

---

### Objetivo General
Diseñar e implementar una herramienta CLI en Go que genere logs estructurados de eventos académicos de registro y modificación de notas y que aplique mecanismos de hashing y cifrado para proteger su integridad, confidencialidad y verificabilidad durante el ciclo de almacenamiento y recuperación.

---

### Resultados de Aprendizaje
* Entender el concepto de una operación sensible dentro de un dominio de negocio realista, desde la perspectiva de atributos y sub-atributos de seguridad.
* Diseñar un log estructurado en formato JSON para representar eventos de registro y modificación de notas, justificando la selección de campos, en pro de la satisfacción de los atributos de calidad considerados.
* Implementar operaciones de hashing y cifrado para brindar integridad a nivel de cada registro y confidencialidad de los registros en su totalidad.

---

### Descripción Funcional
La aplicación deberá guiar al usuario, a través de una interfaz CLI con menú interactivo, en un flujo de trabajo que contemple las siguientes acciones:

* **Paso 1. Definición del volumen de eventos:** la aplicación deberá solicitar al usuario la cantidad de eventos de log a generar.
* **Paso 2. Generación aleatoria de eventos:** la aplicación deberá generar aleatoriamente eventos de dos tipos: *registro de nota* y *modificación de nota*. Cada evento deberá estar representado mediante un objeto JSON estructurado y deberá incluir, como mínimo, identificadores de los actores, recursos y datos involucrados. El modelo deberá orientarse a identificadores únicos o pseudónimos (por ejemplo, UID). El valor de la nota deberá generarse aleatoriamente con distribución uniforme entre 0.0 y 5.0. En el caso de modificación de nota, el evento deberá permitir diferenciar entre el valor anterior y el nuevo valor.
* **Paso 3. Hash del payload de cada operación:** cada evento deberá incluir un hash del payload de la operación, incorporado dentro del mismo log. El reporte técnico de la solución deberá diseñar y justificar qué campos conforman dicho payload y cómo se excluyen del cálculo aquellos campos que harían circular la operación de hashing.
* **Paso 4. Construcción del log estructurado completo:** la aplicación deberá consolidar los eventos generados en un log estructurado en formato JSON. El diseño del esquema del log deberá ser propuesto y justificado por el equipo o estudiante.
* **Paso 5. Hash del log completo en claro/texto plano:** antes de cifrar el archivo, la aplicación deberá calcular el hash del log completo original y almacenarlo de forma separada.
* **Paso 6. Cifrado del log en reposo:** la aplicación deberá cifrar el log completo utilizando mecanismos criptográficos implementados con bibliotecas nativas de Go. El resultado deberá almacenarse como un artefacto separado del log original, así como los insumos requeridos para la operación criptográfica en su totalidad.
* **Paso 7. Hash del log cifrado:** la aplicación deberá calcular el hash del log cifrado y almacenarlo de forma separada.
* **Paso 8. Descifrado del log:** la aplicación deberá recuperar el contenido del log cifrado mediante descifrado, reconstruyendo el artefacto lógico original o su equivalente verificable.
* **Paso 9. Hash del log descifrado:** la aplicación deberá calcular el hash del log descifrado y compararlo con el hash del log original en claro.
* **Paso 10. Presentación de resultados:** la aplicación deberá informar de manera clara al usuario cantidad de eventos generados, tipo de eventos generados, hashes obtenidos en cada etapa, y resultado de la comparación entre log original y log descifrado. La salida deberá permitir concluir si el proceso preservó la información original.

---

### Restricciones Tecnológicas
La solución deberá respetar las siguientes restricciones:
* La implementación debe realizarse en **Go**.
* Para los mecanismos de hashing y criptográficos, se deberán emplear bibliotecas nativas o estándar de Go.
* La aplicación deberá ofrecer una interfaz CLI, guiada por menús y soportada en la reutilización de una librería de terceros orientada a interacción en terminal.

---

### Entregables
El equipo deberá cargar en la plataforma Moodle del curso un archivo `.ZIP` conteniendo:

1. **Archivo .ZIP** con estructura de carpetas de código fuente en Go, incluyendo 2 diagramas de diseño: uno de estructura y otro de comportamiento.
2. **Archivo .PDF** con diapositivas que comuniquen lo realizado en el taller y que sirva de apoyo para el video de sustentación y demostración del taller. Se deben incluir detalles y justificación de diseño y selección de funciones de hashing y criptrográficas. Incluir diapositiva de declaración de uso responsable de IA.
3. **Enlace URL a video de sustentación** del taller, incluido en las diapositivas del proyecto, en el que intervengan todos los integrantes del equipo de trabajo:
   - **Video en YouTube:** [https://www.youtube.com/watch?v=noc2NYgj0c0](https://www.youtube.com/watch?v=noc2NYgj0c0)
   - **Diapositivas Vectoriales:** [presentacion_taller2.pdf](presentacion_taller2.pdf) (o en [docs/presentacion_taller2.pdf](docs/presentacion_taller2.pdf))

---

## 🚀 Guía de Uso de la Utilidad CLI

### 1. Requisitos Previos y Compilación

- **Go:** versión 1.22 o superior (100% biblioteca estándar, Zero CGO).
- **Entorno de terminal:** Bash, Zsh o Git Bash (en Windows obligatorio Git Bash para compatibilidad de comandos POSIX).

```bash
# Compilar binario en carpeta bin/
go build -o bin/cli ./cmd/cli

# O ejecutar directamente con go run
go run ./cmd/cli [flags]
```

### 2. Modos de Ejecución

#### Modo A: Interactivo con Menú Guiado (Por Defecto)
Despliega una interfaz navegable con flechas del teclado (`↑` / `↓`) y selección con `Enter`:

```bash
go run ./cmd/cli
```

**Opciones disponibles en el menú:**
1. `1. Ejecutar Flujo Completo (Pasos 1 al 10)`: ejecuta secuencialmente el pipeline completo, solicita volumen si no se indicó y presenta tablas de hashes y veredicto.
2. `2. Paso 1: Definir volumen de eventos`: solicita interactivamente el número de eventos $N$ ($1 \le N \le 100\,000$).
3. `3. Pasos 2-4: Generar eventos y log consolidado`: genera eventos estocásticos (`REGISTRO_NOTA`, `MODIFICACION_NOTA`), calcula el hash de payload determinista bajo RFC 8785 y escribe `output/academic_log.json`.
4. `4. Pasos 5-7: Hashear y Cifrar log en reposo`: computa SHA-256 en claro (`output/academic_log.json.sha256`), cifra con AES-256-GCM (`output/academic_log.enc`), aísla secretos con permisos POSIX `0600` (`output/crypto_metadata.json`) y computa SHA-256 del ciphertext (`output/academic_log.enc.sha256`).
5. `5. Pasos 8-9: Descifrar y validar integridad`: recupera el log mediante AES-256-GCM verificando el tag GMAC (`output/academic_log_decrypted.json`) y genera su digest (`output/academic_log_decrypted.sha256`).
6. `6. Paso 10: Ver reporte de auditoría y comparativa de hashes`: ejecuta auditoría dual (hash macro de archivo y micro por registro) con comparación en tiempo constante (`subtle.ConstantTimeCompare`).
7. `7. Salir`: finaliza la CLI.

#### Modo B: Automático / Desatendido (CI/CD o Scripts)
Ejecuta todo el pipeline (Pasos 1 al 10) de forma directa sin requerir interacción manual:

```bash
# Ejecutar pipeline completo con 25 eventos
go run ./cmd/cli --auto -n 25

# Usando el binario compilado
./bin/cli --auto --events 50
```

### 3. Banderas (Flags) de la CLI

| Bandera | Tipo | Valor por defecto | Descripción |
| :--- | :---: | :---: | :--- |
| `--auto` | booleano | `false` | Ejecuta el flujo completo (Pasos 1 al 10) sin abrir el menú interactivo. |
| `-n`, `--events` | entero | vacío | Volumen de eventos $N$ a generar ($1 \le N \le 100\,000$). |
| `--version` | booleano | `false` | Imprime la versión de la herramienta y finaliza. |
| `-h`, `--help` | booleano | `false` | Muestra el menú de ayuda con todas las banderas disponibles. |

### 4. Estructura de Artefactos Generados (`output/`)

El sistema aísla los artefactos en el directorio local `output/` aplicando permisos POSIX restrictivos:

```
output/
├── academic_log.json                # Paso 4: Log en texto claro (JSON estructurado)
├── academic_log.json.sha256         # Paso 5: Hash SHA-256 del log original
├── academic_log.enc                 # Paso 6: Log cifrado con AES-256-GCM + Tag GMAC (128-bit)
├── crypto_metadata.json             # Paso 6: Clave AES de 256 bits y Nonce de 96 bits en hex (chmod 0600)
├── academic_log.enc.sha256          # Paso 7: Hash SHA-256 del archivo cifrado
├── academic_log_decrypted.json      # Paso 8: Log recuperado tras descifrado
└── academic_log_decrypted.sha256   # Paso 9: Hash SHA-256 del log descifrado
```

- Permisos de directorio `output/`: `0700` (`drwx------`, acceso exclusivo del usuario propietario).
- Permisos de archivo de secretos `crypto_metadata.json`: `0600` (`-rw-------`, lectura/escritura exclusiva del propietario).

### 5. Pruebas de Resistencia Forense y Detección de Tampering

#### Escenario 1: Bit-Flipping en Datos Cifrados en Reposo
Simula la alteración de 1 byte en el archivo cifrado. AES-256-GCM detecta la mutación gracias al tag GMAC y aborta antes de emitir texto en claro:

```bash
# 1. Ejecutar pipeline base
go run ./cmd/cli --auto -n 10

# 2. Corromper 1 byte del archivo cifrado
python3 -c 'b=bytearray(open("output/academic_log.enc","rb").read()); b[0x4A]^=0xFF; open("output/academic_log.enc","wb").write(b)'

# 3. Intentar descifrar
go run ./cmd/cli # Seleccionar Opción 5: Descifrar
# Resultado: ✖ failed to decrypt log file: cipher authentication tag mismatch: data tampered
```

#### Escenario 2: Manipulación Silenciosa de Datos en Claro
Simula la alteración de una calificación dentro del archivo descifrado. El auditor detecta la divergencia en el hash de archivo y en el hash canónico del registro individual:

```bash
# 1. Modificar fraudulentamente una nota en el log descifrado
sed -i 's/"grade": [0-9.]*/"grade": 0.0/' output/academic_log_decrypted.json

# 2. Correr la auditoría forense
go run ./cmd/cli # Seleccionar Opción 6: Auditoría
# Resultado: [ ✘ ] ALERTA DE SEGURIDAD: VIOLACIÓN DE INTEGRIDAD DETECTADA
# Identifica con precisión: [✘] EVT-REG-00003: Payload Hash Discrepancy!
```

### 6. Códigos de Salida POSIX (Exit Codes)

| Código | Significado |
| :---: | :--- |
| `0` | Ejecución exitosa y/o integridad forense 100% preservada. |
| `1` | Error en pipeline o violación de integridad detectada en auditoría. |
| `2` | Parámetros de entrada o banderas de CLI inválidas. |

### 7. Ejecución de la Suite de Pruebas

Para ejecutar las pruebas unitarias, de integración, concurrencia y detección de anomalías:

```bash
go test -v -race ./...
```

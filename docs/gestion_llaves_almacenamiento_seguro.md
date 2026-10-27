# Gestión del Ciclo de Vida de Llaves Criptográficas y Almacenamiento Seguro en Reposo

## 1. Resumen Ejecutivo

En el diseño de sistemas de información académica y de auditoría forense, la protección de registros en reposo (*Data at Rest*) exige controles rigurosos que garanticen simultáneamente **confidencialidad, integridad, autenticidad y no repudio**. 

Este documento describe la arquitectura criptográfica adoptada para la protección del log estructurado consolidado (`academic_log.json`), implementando cifrado autenticado simétrico **AES-256-GCM**, desacoplamiento físico de artefactos y un modelo de gestión de llaves alineado con los estándares del **NIST SP 800-57** (*Recommendation for Key Management*). Asimismo, se formaliza el modelo de amenazas mitigado y la justificación técnica para la transición hacia infraestructuras basadas en **KMS/HSM** en entornos productivos.

---

## 2. Ciclo de Vida de Llaves Criptográficas (NIST SP 800-57)

El estándar NIST SP 800-57 define las fases operativas por las que transita cualquier material criptográfico. En la solución implementada en Go (`package storage` y `package crypto`), el ciclo de vida se estructura de la siguiente manera:

```
┌────────────────┐      ┌─────────────────┐      ┌─────────────────────────┐
│ 1. Generación  │ ───> │   2. Empleo     │ ───> │ 3. Almacenamiento       │
│  (CSPRNG / SO) │      │  (AES-256-GCM)  │      │  (Desacoplado, hex 0600)│
└────────────────┘      └─────────────────┘      └─────────────────────────┘
                                                              │
                                                              ▼
                        ┌─────────────────┐      ┌─────────────────────────┐
                        │ 5. Destrucción  │ <─── │ 4. Rotación / Reemplazo │
                        │  (Zeroization)  │      │  (Llave única/artefacto)│
                        └─────────────────┘      └─────────────────────────┘
```

### 2.1 Generación Criptográficamente Fuerte

#### Requisito y Fuente de Entropía
Toda clave simétrica de 256 bits debe derivarse de una fuente de números pseudoaleatorios criptográficamente segura (**CSPRNG**). La reutilización de semillas pseudoaleatorias lineales (como `math/rand`) destruye por completo la seguridad de un algoritmo simétrico.

#### Implementación Técnica
La función `GenerateAES256Key()` utiliza el paquete nativo `crypto/rand` de la biblioteca estándar de Go:

```go
func GenerateAES256Key() ([]byte, error) {
    key := make([]byte, 32) // 32 bytes = 256 bits
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return nil, fmt.Errorf("failed to generate secure key: %w", err)
    }
    return key, nil
}
```

- **Plataformas POSIX (Linux/macOS):** `rand.Reader` consulta directamente la llamada al sistema `getrandom(2)` o `/dev/urandom`, alimentado del pool de entropía del kernel (ruido de interrupciones de hardware, temporización de discos y eventos de entrada).
- **Windows:** Se apoya en la API de seguridad criptográfica de Windows (`BCryptGenRandom` / `CryptGenRandom`).
- **Espacio de Búsqueda:** Con 256 bits, el espacio de claves es de $2^{256} \approx 1.1579 \times 10^{77}$ combinaciones posibles, invulnerable a ataques de fuerza bruta presentes y resistente a la computación cuántica (brindando un margen de seguridad post-Grover de 128 bits efectivos).

---

### 2.2 Uso Operativo: Cifrado Autenticado Simétrico (AES-256-GCM)

#### Modo de Operación Galois/Counter Mode (GCM)
Se seleccionó **AES-256 en modo GCM** (definido en **NIST SP 800-38D**) como primitiva criptográfica de tipo **AEAD** (*Authenticated Encryption with Associated Data*):

1. **Confidencialidad:** Cifra los bloques de datos aplicando AES sobre un contador incremental (CTR mode).
2. **Integridad y Autenticidad:** Genera un código de autenticación de mensaje de Galois (**GMAC**) denominado *Authentication Tag* de 128 bits (16 bytes).

```
Texto Claro ──────► [ AES-CTR Encryption ] ──────► Ciphertext (academic_log.enc)
                          ▲                              │
             Llave (32B) ─┤                              ▼
             Nonce (12B) ─┴──────────────► [ GMAC ] ──► Auth Tag (16B al final)
```

#### Gestión Crítica del Nonce (Number Used Once)
- **Dimensión:** Exactamente 96 bits (12 bytes), tamaño estándar que optimiza el desempeño y evita la fase de hashing GHASH previa del IV.
- **Regla Fundamental:** El par $(\text{Llave}, \text{Nonce})$ **jamás debe reutilizarse**. La colisión de un nonce bajo la misma llave en GCM compromete la llave de autenticación de Galois ($H$), permitiendo ataques de falsificación de mensajes y recuperación del texto claro.
- **Estrategia Implementada:** Cada invocación de `EncryptLogFile` genera un nonce nuevo e independiente mediante CSPRNG, garantizando una probabilidad de colisión despreciable ($< 2^{-32}$ bajo el límite de mensajes recomendado por NIST).

---

### 2.3 Almacenamiento Físicamente Desacoplado de Insumos

Para mitigar riesgos de divulgación masiva y cumplir con el principio de separación de privilegios, los artefactos del proceso residen en archivos independientes:

| Artefacto | Archivo | Rol Criptográfico | Formato / Permisos |
| :--- | :--- | :--- | :--- |
| **Log Cifrado** | `academic_log.enc` | Ciphertext puro concatenado con el Auth Tag | Binario crudo (`0600`) |
| **Insumos Criptográficos** | `crypto_metadata.json` | Parámetros necesarios para el descifrado | JSON estandarizado (`0600`) |

#### Estructura del Archivo de Metadatos (`crypto_metadata.json`)
Los insumos binarios se serializan en codificación hexadecimal estándar para facilitar su transmisión, serialización JSON e inspección técnica:

```json
{
  "algorithm": "AES-256-GCM",
  "key_hex": "4f9d2c18b76e1a03f4d89a2bc0e57f123456789abcdef0123456789abcdef012",
  "nonce_hex": "e1f2a3b4c5d6e7f8a9b0c1d2",
  "auth_tag_size": 16,
  "created_at": "2026-10-26T20:00:00Z"
}
```

#### Restricciones de Sistema de Archivos
- **Permisos de Directorio:** `0700` (`drwx------`), impidiendo que usuarios del sistema ajenos al propietario listen o accedan a la carpeta `output/`.
- **Permisos de Archivos:** `0600` (`-rw-------`), garantizando que solo el proceso ejecutor posea privilegios de lectura y escritura.

---

### 2.4 Rotación y Destrucción Segura (*Zeroization*)

#### Modelo de Rotación por Artefacto
El diseño adopta la premisa de **clave efímera por archivo de log**. No existe una clave maestra persistente compartida entre diferentes ejecuciones; cada consolidación de log deriva una clave y un nonce frescos.

#### Destrucción en Memoria (*Zeroization*)
En aplicaciones que procesan material criptográfico confidencial, la retención de claves en la memoria RAM tras completar las operaciones expone el secreto a volcados de memoria (*core dumps*), ataques de lectura lateral o hibernación en swap:

1. **Práctica en Go:** Los slices que contienen la clave (`key`) y el nonce (`nonce`) deben sobrescribirse explícitamente con ceros una vez utilizados:
   ```go
   func Zeroize(b []byte) {
       for i := range b {
           b[i] = 0
       }
   }
   ```
2. **Consideraciones del Garbage Collector (GC):** Dado que Go es un lenguaje con recolección de basura y gestión automática de memoria, las copias intermedias de strings o structs pueden permanecer temporalmente en el heap hasta su recolección. Por esta razón, el manejo de claves en memoria binaria cruda (`[]byte`) es preferido sobre tipos inmutables como `string`.

---

## 3. Modelo de Amenazas y Vectores Mitigados

### 3.1 Mitigación de Lectura no Autorizada (Confidencialidad)

- **Vector de Ataque:** Exfiltración física del medio de almacenamiento, acceso indebido por usuarios del sistema operativo sin privilegios o filtración accidental del archivo de log.
- **Mecanismo de Mitigación:** Al almacenar el archivo `academic_log.enc` bajo AES-256, cualquier adversario que obtenga el artefacto cifrado sin poseer la clave simétrica se enfrenta a un problema computacionalmente intratable. La entropía del ciphertext es máxima e indistinguible de ruido pseudoaleatorio puro.

---

### 3.2 Mitigación de Manipulación o Reemplazo de Registros (Integridad y Autenticidad)

- **Vector de Ataque:** Un atacante con acceso al sistema de archivos intenta alterar calificaciones, suplantar la firma de un docente o truncar eventos dentro del log cifrado.
- **Mecanismo de Mitigación Multicapa:**
  1. **Autenticación Criptográfica a Nivel de Bloque (GCM Auth Tag):** Cualquier modificación de un solo bit en `academic_log.enc` ocasiona que `cipher.AEAD.Open` rechace el descifrado con un error de autenticación:
     $$\text{Verification Failure} \implies \text{Descifrado Rechazado}$$
  2. **Testigos Criptográficos Globales (SHA-256):** Los archivos `academic_log.json.sha256` y `academic_log.enc.sha256` desacoplados permiten verificar de forma determinista e inmediata si el archivo fue reemplazado en su totalidad por una versión previa legítima (*Rollback / Replay Attack*).

---

### 3.3 Análisis de Riesgo: Almacenamiento en Disco vs. HSM / KMS en Producción

#### Debilidad del Modelo Didáctico Local
En la implementación actual, tanto el archivo cifrado (`academic_log.enc`) como sus insumos (`crypto_metadata.json`) residen en el mismo medio físico (`output/`). Si un atacante compromete la cuenta del usuario del sistema operativo o el servidor completo (*Root / Host Compromise*), puede leer simultáneamente el ciphertext y la clave en claro (`key_hex`), neutralizando la protección criptográfica.

```
RIESGO EN DISCO LOCAL:
Compromiso del Host ──► Acceso a output/ ──► [ academic_log.enc + crypto_metadata.json ]
                                                             │
                                                             ▼
                                             Descifrado Inmediato por el Atacante
```

#### Arquitectura Recomendada para Producción: HSM / KMS

Para mitigar este riesgo en entornos de misión crítica, los insumos criptográficos deben segregarse utilizando un **Hardware Security Module (HSM)** o un servicio de gestión de claves (**KMS**):

```
ARQUITECTURA DE PRODUCCIÓN (ENVELOPE ENCRYPTION):

                      ┌──────────────────────────────────────────────┐
                      │    KMS / HSM (FIPS 140-2/3 Level 3/4)        │
                      │                                              │
                      │   [ Key Encryption Key (KEK) - No Extraíble ]│
                      └──────────────────────┬───────────────────────┘
                                             │
                        1. GenerateDataKey() │ 2. Devuelve:
                                             │    - DEK en Claro (Uso efímero)
                                             │    - DEK Cifrada (Encrypted Key)
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │             Servidor de Aplicación           │
                      │                                              │
                      │  • Cifra Log con DEK en Claro                │
                      │  • Destruye DEK en Claro (Zeroize RAM)       │
                      │  • Almacena solo DEK Cifrada                 │
                      └──────────────┬───────────────────────────────┘
                                     │
                                     ▼
                ┌─────────────────────────────────────────┐
                │          Almacenamiento Local           │
                │                                         │
                │  • academic_log.enc (Ciphertext)        │
                │  • crypto_metadata.json                 │
                │    └── "encrypted_key_blob": "AQEDAH..."│
                └─────────────────────────────────────────┘
```

#### Ventajas del Modelo KMS/HSM (e.g., HashiCorp Vault, AWS KMS, Google Cloud KMS):

1. **Envelope Encryption (Cifrado de Sobre):**
   - La clave que cifra el log es una **Data Encryption Key (DEK)**.
   - La DEK se almacena cifrada mediante una **Key Encryption Key (KEK)** que reside exclusivamente dentro de la frontera criptográfica segura del HSM y **nunca puede ser exportada en texto claro**.
2. **Aislamiento Físico y Blindaje contra Manipulación:**
   - Dispositivos certificados **FIPS 140-2/140-3 Nivel 3 o 4** destruyen automáticamente el material criptográfico ante intrusión física o análisis térmico/eléctrico.
3. **Pistas de Auditoría Inmutables:**
   - Cada solicitud de cifrado o descifrado de una clave genera un registro de auditoría externo inalterable (e.g., CloudTrail, Vault Audit Log), impidiendo el uso encubierto de las llaves.
4. **Control de Acceso Basado en Políticas (RBAC / ABAC):**
   - El descifrado del log requiere privilegios específicos a nivel de IAM o identidades de máquina (Service Accounts, AppRole), separando el rol de administrador de almacenamiento del rol de auditor criptográfico.

---

## 4. Conclusión

El diseño adoptado en el proyecto garantiza que el log académico repose en un estado matemáticamente seguro, respaldado por algoritmos estándar de la industria (AES-256-GCM y SHA-256) y segregación física estricta de artefactos. 

La persistencia de insumos en `crypto_metadata.json` satisface los requerimientos de inspección, portabilidad y auditoría forense del taller, manteniendo documentado el camino de elevación hacia esquemas de **Envelope Encryption** respaldados por hardware para implementaciones de alta criticidad en producción.

# Justificación Técnica: Cálculo y Persistencia de Hashes Globales (US-05)

## 1. Resumen Ejecutivo y Alcance

En la arquitectura de auditoría forense para la protección de logs estructurados en reposo, el cómputo y la persistencia desacoplada de resúmenes criptográficos globales (**digests SHA-256**) constituyen la **cadena de custodia digital** del ciclo de vida de los datos.

La historia de usuario **US-05** implementa los mecanismos criptográficos para los **Pasos 5, 7 y 9** del taller:
1. **Paso 5:** Generación y persistencia del testigo criptográfico del log original en texto claro (`academic_log.json` $\to$ `academic_log.json.sha256`).
2. **Paso 7:** Generación y persistencia del testigo criptográfico del artefacto cifrado (`academic_log.enc` $\to$ `academic_log.enc.sha256`).
3. **Paso 9:** Cómputo del hash del artefacto recuperado tras descifrado (`academic_log_decrypted.json` $\to$ digest en memoria / persistido) para comparación contra el original.

---

## 2. Decisiones de Arquitectura e Ingeniería Criptográfica

### 2.1 Procesamiento por Streaming ($O(1)$ en Memoria RAM)

#### Problema Técnico
Cargar la totalidad del archivo de log o del archivo cifrado a un buffer en memoria RAM (`os.ReadFile`) para calcular el hash presenta graves debilidades en entornos de producción y auditoría:
- Consumo de memoria proporcional al tamaño del archivo ($O(N)$), haciendo la aplicación vulnerable a ataques de denegación de servicio por agotamiento de memoria (**OOM - Out of Memory**) ante logs de cientos de megabytes o gigabytes.
- Presión innecesaria sobre el recolector de basura (*Garbage Collector*) de Go.

#### Solución Implementada
La función `ComputeFileSHA256` lee los bytes del archivo en disco de forma incremental mediante streaming utilizando `io.Copy` canalizado directamente hacia la instancia nativa del algoritmo en `crypto/sha256`:

```go
file, err := os.Open(cleanPath)
if err != nil {
    return "", err
}
defer file.Close()

return ComputeStreamSHA256(file) // io.Copy(hasher, file)
```

- **Complejidad espacial:** $O(1)$ estricto, operando a través del buffer interno de 32 KB de `io.Copy`.
- **Aceleración por Hardware:** Aprovecha las extensiones nativas del microprocesador (Intel SHA-NI o ARMv8 Crypto Extensions) habilitadas automáticamente por la biblioteca estándar de Go.

---

### 2.2 Formato Estándar BSD / GNU Coreutils (`sha256sum`)

Para garantizar **interoperabilidad forense** y permitir que cualquier auditor externo o herramienta del sistema operativo verifique la integridad sin depender exclusivamente de nuestro binario, los archivos de digest se almacenan respetando estrictamente el formato de **GNU Coreutils**:

```text
<hash_hexadecimal_64_caracteres>  <nombre_base_del_archivo>\n
```

- **Delimitador estándar:** Exactamente **dos espacios** (`0x20 0x20`), correspondiente a la especificación de verificación en modo texto de coreutils.
- **Ruta desacoplada:** Se incluye únicamente el nombre base (`filepath.Base`), permitiendo la verificación portable mediante utilitarios estándar como:
  ```bash
  sha256sum -c academic_log.json.sha256
  # Salida: academic_log.json: OK
  ```
- **Flexibilidad de parseo:** El parser `ParseCoreutilsDigest` implementado reconoce tanto el estándar de dos espacios (`"  "`), como el modo binario (`" *"`) y líneas con comentarios (`#`), normalizando la validación a minúsculas y verificando longitud estricta de 256 bits (64 caracteres hex).

---

### 2.3 Resistencia contra Ataques de Canal Lateral (Timing Attacks)

La función `CompareDigests` y la verificación forense `VerifyFileAgainstDigestFile` utilizan comparación en tiempo constante:

```go
subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
```

A diferencia de la comparación estándar de strings (`==`), que retorna de inmediato al primer caracter discordante (filtrando información del prefijo mediante microsegundos de CPU medibles por un atacante), `ConstantTimeCompare` ejecuta un número invariable de ciclos de reloj independientemente de la coincidencia o discordancia, mitigando vulnerabilidades de canal lateral temporal.

---

## 3. Trazabilidad del Ciclo de Vida del Log en Reposo

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│ CICLO DE VIDA DEL LOG Y TESTIGOS CRIPTOGRÁFICOS INDEPENDIENTES                   │
└──────────────────────────────────────────────────────────────────────────────────┘

   [ Paso 4: Log Consolidado ]
                │
                ▼
      academic_log.json ─────────────────────► HashPlaintextLog (Paso 5)
                │                                       │
                │                                       ▼
                │                            academic_log.json.sha256
                │                           (Testigo Original en Claro)
                ▼
       [ Paso 6: Cifrado AES-GCM ]
                │
                ▼
      academic_log.enc ──────────────────────► HashEncryptedLog (Paso 7)
                │                                       │
                │                                       ▼
                │                             academic_log.enc.sha256
                │                           (Testigo Artefacto Cifrado)
                ▼
      [ Paso 8: Descifrado ]
                │
                ▼
 academic_log_decrypted.json ────────────────► HashDecryptedLog (Paso 9)
                                                        │
                                                        ▼
                                                Digest Recuperado
                                                        │
                                                        ▼
                                         [ Paso 9/10: Verificación Forense ]
                                          ¿Digest Original == Digest Descifrado?
                                          ✔ Integridad y Preservación Demostrada
```

---

## 4. Matriz de Cumplimiento Técnico (Definition of Done)

| Criterio DoD | Evidencia de Implementación | Estado |
| :--- | :--- | :--- |
| **Streaming directo con `io.Copy`** | `ComputeFileSHA256` y `ComputeStreamSHA256` operan sobre `io.Reader` sin cargar archivos completos a RAM. | Cumplido |
| **Persistencia Coreutils (`<hash>  <filename>`)** | `FormatCoreutilsDigest` y `HashAndPersistFileSHA256` escriben `<hash>  <filename>\n`. | Cumplido |
| **Cobertura de Pasos 5, 7 y 9** | Métodos `HashPlaintextLog`, `HashEncryptedLog` y `HashDecryptedLog` en interfaz `GlobalHasher`. | Cumplido |
| **Comparación de tiempo constante** | Implementación de `CompareDigests` con `crypto/subtle.ConstantTimeCompare`. | Cumplido |
| **Tests con vectores sintéticos** | Suite en `global_hasher_test.go` cubriendo vectores NIST, archivos sintéticos de gran tamaño, detección de adulteración de 1 bit, concurrencia y validación de errores. | Cumplido |

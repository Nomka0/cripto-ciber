package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashEncryptedLog(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Crear un artefacto cifrado sintético simulando el Paso 6 (academic_log.enc) con bytes binarios crudos
	cipherPath := filepath.Join(tempDir, "academic_log.enc")
	hashOutputPath := filepath.Join(tempDir, "academic_log.enc.sha256")

	// Payload binario crudo (simula nonce + ciphertext AES-GCM + tag de autenticación)
	rawCiphertext := make([]byte, 2048)
	if _, err := rand.Read(rawCiphertext); err != nil {
		for i := range rawCiphertext {
			rawCiphertext[i] = byte((i*37 + 19) % 256)
		}
	}
	// Forzar presencia de bytes no imprimibles, nulos y límites para comprobar que lee binario crudo
	rawCiphertext[0] = 0x00
	rawCiphertext[1] = 0xFF
	rawCiphertext[2] = 0x7F
	rawCiphertext[3] = 0x80

	if err := os.WriteFile(cipherPath, rawCiphertext, 0644); err != nil {
		t.Fatalf("failed to write raw ciphertext artifact: %v", err)
	}

	// 2. Ejecutar ComputeAndPersistEncryptedLogHash (Paso 7)
	computedHash, err := ComputeAndPersistEncryptedLogHash(cipherPath, hashOutputPath)
	if err != nil {
		t.Fatalf("ComputeAndPersistEncryptedLogHash failed unexpectedly: %v", err)
	}

	// Criterio de éxito 1: El archivo .sha256 se genera en la ruta especificada
	if _, err := os.Stat(hashOutputPath); err != nil {
		t.Fatalf("expected hash file %s was not created on disk: %v", hashOutputPath, err)
	}

	// Criterio de éxito 2: Su contenido coincide con el hash del archivo cifrado
	savedContent, err := os.ReadFile(hashOutputPath)
	if err != nil {
		t.Fatalf("failed to read persisted hash file: %v", err)
	}
	savedHash := strings.TrimSpace(string(savedContent))

	if savedHash != computedHash {
		t.Errorf("content of hash file does not match returned hash:\nfile content: %q\nreturned:     %q",
			savedHash, computedHash)
	}

	// Criterio de éxito 3: El hash computado coincide con el SHA-256 nativo de los bytes crudos
	expectedSum := sha256.Sum256(rawCiphertext)
	expectedHex := hex.EncodeToString(expectedSum[:])
	if computedHash != expectedHex {
		t.Errorf("computed hash does not match raw binary SHA-256 digest:\nexpected: %s\ngot:      %s",
			expectedHex, computedHash)
	}

	// 3. Reglas de Seguridad:
	// El archivo no debe contener ningún dato sensible de la llave simétrica ni del ciphertext,
	// solo el digest hexadecimal (64 caracteres [0-9a-f]).
	if len(savedHash) != 64 {
		t.Errorf("hash file must only contain 64 hex characters, got length %d", len(savedHash))
	}
	for _, c := range savedHash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("security violation: hash file contains non-hex character '%c'", c)
		}
	}
	if bytes.Contains(savedContent, rawCiphertext[:16]) {
		t.Errorf("security violation: hash file leaked raw ciphertext bytes!")
	}

	// 4. Propiedad de Difusión Criptográfica:
	// El hash del cifrado debe ser radicalmente distinto del hash en claro
	samplePlaintext := []byte(`[{"event_id":"EVT-001","type":"REGISTRO_NOTA","payload":{"grade":4.8}}]`)
	plaintextSum := sha256.Sum256(samplePlaintext)
	plaintextHash := hex.EncodeToString(plaintextSum[:])

	if computedHash == plaintextHash {
		t.Errorf("cryptographic failure: ciphertext hash is identical to plaintext hash!")
	}

	differingChars := 0
	for i := 0; i < len(computedHash) && i < len(plaintextHash); i++ {
		if computedHash[i] != plaintextHash[i] {
			differingChars++
		}
	}
	// Difusión esperada en SHA-256: avalancha masiva (> 70% divergencia de caracteres)
	if differingChars < 40 {
		t.Errorf("diffusion failure: insufficient character divergence (%d/64)", differingChars)
	}
}

func TestHashFile_ValidationAndErrors(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Ruta vacía
	if _, err := HashFile(""); !errors.Is(err, ErrEmptyFilePath) {
		t.Errorf("expected ErrEmptyFilePath, got %v", err)
	}
	if _, err := HashFile("   "); !errors.Is(err, ErrEmptyFilePath) {
		t.Errorf("expected ErrEmptyFilePath for whitespace, got %v", err)
	}

	// 2. Archivo inexistente
	if _, err := HashFile(filepath.Join(tempDir, "missing.enc")); err == nil {
		t.Errorf("expected error for missing file, got nil")
	}

	// 3. Directorio en lugar de archivo regular
	subDir := filepath.Join(tempDir, "some_dir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if _, err := HashFile(subDir); !errors.Is(err, ErrNotRegularFile) {
		t.Errorf("expected ErrNotRegularFile for directory, got %v", err)
	}
}

func TestSaveHashToFile_Validations(t *testing.T) {
	tempDir := t.TempDir()
	validHash := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	// 1. Hash vacío
	if err := SaveHashToFile("", filepath.Join(tempDir, "test.sha256")); err == nil {
		t.Errorf("expected error for empty hash, got nil")
	}

	// 2. Longitud inválida (menor a 64 chars)
	if err := SaveHashToFile("abcd", filepath.Join(tempDir, "test.sha256")); !errors.Is(err, ErrInvalidDigestLength) {
		t.Errorf("expected ErrInvalidDigestLength, got %v", err)
	}

	// 3. Ruta de salida vacía
	if err := SaveHashToFile(validHash, ""); !errors.Is(err, ErrEmptyFilePath) {
		t.Errorf("expected ErrEmptyFilePath, got %v", err)
	}

	// 4. Guardado con creación automática de subdirectorios
	nestedOutput := filepath.Join(tempDir, "nested", "sub", "artifact.sha256")
	if err := SaveHashToFile(validHash, nestedOutput); err != nil {
		t.Fatalf("failed to save hash to nested output: %v", err)
	}

	content, err := os.ReadFile(nestedOutput)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if string(content) != validHash {
		t.Errorf("expected content %s, got %s", validHash, string(content))
	}
}

func TestComputeAndPersistPlaintextLogHash(t *testing.T) {
	tempDir := t.TempDir()
	plainPath := filepath.Join(tempDir, "academic_log.json")
	hashOutputPath := filepath.Join(tempDir, "academic_log.json.sha256")

	plainContent := []byte(`{"academic_records": [{"event_id": "EVT-100", "grade": 5.0}]}`)
	if err := os.WriteFile(plainPath, plainContent, 0644); err != nil {
		t.Fatalf("failed to write plain file: %v", err)
	}

	hash, err := ComputeAndPersistPlaintextLogHash(plainPath, hashOutputPath)
	if err != nil {
		t.Fatalf("ComputeAndPersistPlaintextLogHash failed: %v", err)
	}

	expectedSum := sha256.Sum256(plainContent)
	expectedHex := hex.EncodeToString(expectedSum[:])
	if hash != expectedHex {
		t.Errorf("hash mismatch: expected %s, got %s", expectedHex, hash)
	}

	savedBytes, err := os.ReadFile(hashOutputPath)
	if err != nil {
		t.Fatalf("failed to read hash output: %v", err)
	}
	if string(savedBytes) != expectedHex {
		t.Errorf("persisted hash mismatch: expected %s, got %s", expectedHex, string(savedBytes))
	}
}

func TestHashDecryptedLog(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Simular archivo descifrado (Paso 9: academic_log_decrypted.json)
	decryptedLogPath := filepath.Join(tempDir, "academic_log_decrypted.json")
	sampleDecryptedJSON := []byte(`[
  {"event_id": "EVT-REG-001", "type": "REGISTRO_NOTA", "grade": 4.5},
  {"event_id": "EVT-MOD-002", "type": "MODIFICACION_NOTA", "previous_grade": 4.5, "new_grade": 4.8}
]`)

	if err := os.WriteFile(decryptedLogPath, sampleDecryptedJSON, 0644); err != nil {
		t.Fatalf("failed to write decrypted log file: %v", err)
	}

	// 2. Ejecutar ComputeDecryptedLogHash
	decryptedHash, err := ComputeDecryptedLogHash(decryptedLogPath)
	if err != nil {
		t.Fatalf("ComputeDecryptedLogHash returned unexpected error: %v", err)
	}

	// Criterio de éxito 1: Debe devolver el digest exacto del archivo descifrado (64 chars hex minúsculas)
	expectedSum := sha256.Sum256(sampleDecryptedJSON)
	expectedHex := hex.EncodeToString(expectedSum[:])

	if decryptedHash != expectedHex {
		t.Errorf("digest mismatch for decrypted log:\nexpected: %s\ngot:      %s",
			expectedHex, decryptedHash)
	}

	if len(decryptedHash) != 64 {
		t.Fatalf("expected 64 hex characters, got %d", len(decryptedHash))
	}

	// Criterio de éxito 2: Validar equivalencia con ComputeBytesHash directamente desde buffer en RAM
	memoryHash := ComputeBytesHash(sampleDecryptedJSON)
	if memoryHash != decryptedHash {
		t.Errorf("ComputeBytesHash in RAM differs from ComputeDecryptedLogHash on disk:\nRAM:  %s\nDisk: %s",
			memoryHash, decryptedHash)
	}

	// Criterio de éxito 3: Paso 9 auditoría forense - comparar con el log original en claro
	originalLogPath := filepath.Join(tempDir, "academic_log.json")
	if err := os.WriteFile(originalLogPath, sampleDecryptedJSON, 0644); err != nil {
		t.Fatalf("failed to write original log file: %v", err)
	}
	originalHash, err := HashFile(originalLogPath)
	if err != nil {
		t.Fatalf("failed to hash original file: %v", err)
	}

	if decryptedHash != originalHash {
		t.Errorf("forensic failure: decrypted log hash does not match original plaintext log hash")
	}

	// Casos de error
	if _, err := ComputeDecryptedLogHash(""); !errors.Is(err, ErrEmptyFilePath) {
		t.Errorf("expected ErrEmptyFilePath for empty path, got %v", err)
	}

	if _, err := ComputeDecryptedLogHash(filepath.Join(tempDir, "non_existent_decrypted.json")); err == nil {
		t.Errorf("expected error for non-existent file, got nil")
	}
}


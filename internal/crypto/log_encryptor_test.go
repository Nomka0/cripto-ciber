package crypto

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptLogFile(t *testing.T) {
	tempDir := t.TempDir()

	// Crear archivo de log simulado
	logPath := filepath.Join(tempDir, "academic_log.json")
	logContent := []byte(`[
  {"event_id":"EVT-REG-00001","event_type":"REGISTRO_NOTA","payload":{"student_uid":"USR-STU-001","grade":4.5},"payload_hash":"abc123"},
  {"event_id":"EVT-REG-00002","event_type":"REGISTRO_NOTA","payload":{"student_uid":"USR-STU-002","grade":3.8},"payload_hash":"def456"},
  {"event_id":"EVT-MOD-00003","event_type":"MODIFICACION_NOTA","payload":{"student_uid":"USR-STU-001","previous_grade":4.5,"new_grade":4.8},"payload_hash":"ghi789"}
]`)

	if err := os.WriteFile(logPath, logContent, 0644); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}

	// 1. Ejecutar EncryptLogFile
	artifacts, err := EncryptLogFile(logPath)
	if err != nil {
		t.Fatalf("EncryptLogFile failed unexpectedly: %v", err)
	}

	// Criterio de éxito 1: algoritmo debe ser "AES-256-GCM"
	if artifacts.Algorithm != "AES-256-GCM" {
		t.Errorf("expected algorithm 'AES-256-GCM', got %q", artifacts.Algorithm)
	}

	// Criterio de éxito 2: tamaño del ciphertext = len(plaintext) + 16 (GCM tag)
	expectedCiphertextSize := int64(len(logContent)) + 16
	if artifacts.CiphertextSize != expectedCiphertextSize {
		t.Errorf("ciphertext size mismatch: expected %d, got %d",
			expectedCiphertextSize, artifacts.CiphertextSize)
	}
	if int64(len(artifacts.Ciphertext)) != expectedCiphertextSize {
		t.Errorf("actual ciphertext slice length mismatch: expected %d, got %d",
			expectedCiphertextSize, len(artifacts.Ciphertext))
	}

	// Criterio de éxito 3: PlaintextSize refleja el tamaño original
	if artifacts.PlaintextSize != int64(len(logContent)) {
		t.Errorf("plaintext size mismatch: expected %d, got %d",
			int64(len(logContent)), artifacts.PlaintextSize)
	}

	// Criterio de éxito 4: Llave = 32 bytes, Nonce = 12 bytes
	if len(artifacts.Key) != AES256KeySize {
		t.Errorf("key length mismatch: expected %d, got %d", AES256KeySize, len(artifacts.Key))
	}
	if len(artifacts.Nonce) != GCMNonceSize {
		t.Errorf("nonce length mismatch: expected %d, got %d", GCMNonceSize, len(artifacts.Nonce))
	}

	// Criterio de éxito 5: El ciphertext no contiene el plaintext (cifrado efectivo)
	if bytes.Contains(artifacts.Ciphertext, logContent) {
		t.Errorf("security failure: ciphertext contains raw plaintext bytes")
	}

	// Criterio de éxito 6: EncryptedAt es un timestamp UTC no nulo
	if artifacts.EncryptedAt.IsZero() {
		t.Errorf("expected non-zero EncryptedAt timestamp")
	}
}

func TestEncryptLogFile_Freshness(t *testing.T) {
	// Cada invocación debe producir llave y nonce distintos (nunca reutilizar material criptográfico)
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "academic_log.json")
	if err := os.WriteFile(logPath, []byte(`{"events":[]}`), 0644); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	a1, err := EncryptLogFile(logPath)
	if err != nil {
		t.Fatalf("first EncryptLogFile failed: %v", err)
	}
	a2, err := EncryptLogFile(logPath)
	if err != nil {
		t.Fatalf("second EncryptLogFile failed: %v", err)
	}

	if bytes.Equal(a1.Key, a2.Key) {
		t.Errorf("CRITICAL: same key generated in two distinct invocations (key reuse!)")
	}
	if bytes.Equal(a1.Nonce, a2.Nonce) {
		t.Errorf("CRITICAL: same nonce generated in two distinct invocations (nonce reuse!)")
	}
	if bytes.Equal(a1.Ciphertext, a2.Ciphertext) {
		t.Errorf("CRITICAL: identical ciphertext from two invocations — randomness failure")
	}
}

func TestEncryptLogFile_ErrorCases(t *testing.T) {
	// 1. Ruta vacía
	if _, err := EncryptLogFile(""); !errors.Is(err, ErrEmptyFilePath) {
		t.Errorf("expected ErrEmptyFilePath for empty path, got %v", err)
	}
	// 2. Archivo inexistente
	if _, err := EncryptLogFile("/non_existent/path/log.json"); err == nil {
		t.Errorf("expected error for non-existent file, got nil")
	}
}

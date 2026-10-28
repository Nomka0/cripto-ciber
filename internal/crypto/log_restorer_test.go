package crypto

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"taller2-criptografia/internal/storage"
)

// encryptTestLog escribe un log en claro en dir, lo cifra y persiste academic_log.enc y crypto_metadata.json.
func encryptTestLog(t *testing.T, dir string) []byte {
	t.Helper()
	original := []byte(`{"events":[{"event_id":"EVT-001","type":"REGISTRO_NOTA","payload":{"grade":4.5}},` +
		`{"event_id":"EVT-002","type":"MODIFICACION_NOTA","payload":{"old_grade":3.1,"new_grade":4.0}}]}`)

	if err := os.WriteFile(storage.GetPlaintextLogPath(dir), original, 0600); err != nil {
		t.Fatalf("failed to write plaintext log: %v", err)
	}
	artifacts, err := EncryptLogFile(storage.GetPlaintextLogPath(dir))
	if err != nil {
		t.Fatalf("EncryptLogFile failed: %v", err)
	}
	if err := storage.SaveCiphertext(storage.GetEncryptedLogPath(dir), artifacts.Ciphertext); err != nil {
		t.Fatalf("SaveCiphertext failed: %v", err)
	}
	if err := storage.SaveCryptoMetadata(storage.GetCryptoMetadataPath(dir), artifacts.Key, artifacts.Nonce); err != nil {
		t.Fatalf("SaveCryptoMetadata failed: %v", err)
	}
	return original
}

func TestRestoreDecryptedLogFile(t *testing.T) {
	dir := t.TempDir()
	original := encryptTestLog(t, dir)
	outPath := storage.GetDecryptedLogPath(dir)

	plaintext, err := RestoreDecryptedLogFile(storage.GetEncryptedLogPath(dir), storage.GetCryptoMetadataPath(dir), outPath)
	if err != nil {
		t.Fatalf("RestoreDecryptedLogFile failed: %v", err)
	}
	if !bytes.Equal(original, plaintext) {
		t.Errorf("in-memory plaintext differs from original")
	}

	onDisk, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("decrypted file not readable: %v", err)
	}
	if !bytes.Equal(original, onDisk) {
		t.Errorf("academic_log_decrypted.json differs from academic_log.json")
	}

	// Paso 9: el hash del log descifrado debe coincidir con el del original.
	origHash, err := HashFile(storage.GetPlaintextLogPath(dir))
	if err != nil {
		t.Fatalf("HashFile(original) failed: %v", err)
	}
	decHash, err := HashFile(outPath)
	if err != nil {
		t.Fatalf("HashFile(decrypted) failed: %v", err)
	}
	if origHash != decHash {
		t.Errorf("hash mismatch: original %s, decrypted %s", origHash, decHash)
	}
}

func TestRestoreDecryptedLogFileTampered(t *testing.T) {
	dir := t.TempDir()
	encryptTestLog(t, dir)
	encPath := storage.GetEncryptedLogPath(dir)
	outPath := storage.GetDecryptedLogPath(dir)

	ciphertext, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("failed to read ciphertext: %v", err)
	}
	ciphertext[0] ^= 0x01
	if err := os.WriteFile(encPath, ciphertext, 0600); err != nil {
		t.Fatalf("failed to write tampered ciphertext: %v", err)
	}

	plaintext, err := RestoreDecryptedLogFile(encPath, storage.GetCryptoMetadataPath(dir), outPath)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("expected ErrAuthenticationFailed, got %v", err)
	}
	if plaintext != nil {
		t.Errorf("plaintext leaked on failure")
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Errorf("decrypted file must not be written on authentication failure")
	}
}

func TestRestoreDecryptedLogFileMissingInputs(t *testing.T) {
	dir := t.TempDir()
	outPath := storage.GetDecryptedLogPath(dir)

	if _, err := RestoreDecryptedLogFile(storage.GetEncryptedLogPath(dir), storage.GetCryptoMetadataPath(dir), outPath); err == nil {
		t.Errorf("expected error for missing crypto metadata")
	}

	encryptTestLog(t, dir)
	if err := os.Remove(storage.GetEncryptedLogPath(dir)); err != nil {
		t.Fatalf("failed to remove ciphertext: %v", err)
	}
	if _, err := RestoreDecryptedLogFile(storage.GetEncryptedLogPath(dir), storage.GetCryptoMetadataPath(dir), outPath); err == nil {
		t.Errorf("expected error for missing encrypted log")
	}
}

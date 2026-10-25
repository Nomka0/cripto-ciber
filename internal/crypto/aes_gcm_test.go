package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestAESGCMEncryption(t *testing.T) {
	enc := NewAESGCMEncryptor()

	// Generar llave aleatoria de 32 bytes (AES-256) y nonce de 12 bytes
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	plaintext := []byte(`[{"event_id":"EVT-001","type":"REGISTRO_NOTA","payload":{"grade":4.5}}]`)

	// 1. Criterio de éxito: ciphertext tiene exactamente len(plaintext) + 16 bytes (GCM tag)
	ciphertext, err := enc.Encrypt(plaintext, key, nonce)
	if err != nil {
		t.Fatalf("Encrypt failed unexpectedly: %v", err)
	}

	expectedLen := len(plaintext) + 16
	if len(ciphertext) != expectedLen {
		t.Errorf("ciphertext length mismatch: expected %d (plaintext %d + 16 tag), got %d",
			expectedLen, len(plaintext), len(ciphertext))
	}

	// 2. El ciphertext no debe coincidir con el plaintext original
	if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
		t.Errorf("security failure: ciphertext stream matches plaintext")
	}

	// 3. Reproducibilidad determinista: mismos inputs -> mismo ciphertext
	ciphertext2, err := enc.Encrypt(plaintext, key, nonce)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}
	if !bytes.Equal(ciphertext, ciphertext2) {
		t.Errorf("expected deterministic output for same key+nonce, got different results")
	}

	// 4. Nonce distinto -> ciphertext radicalmente diferente (efecto de difusión del CTR subyacente)
	nonce2 := make([]byte, 12)
	copy(nonce2, nonce)
	nonce2[11] ^= 0x01 // cambiar un solo bit del nonce

	ciphertextNonce2, err := enc.Encrypt(plaintext, key, nonce2)
	if err != nil {
		t.Fatalf("Encrypt with different nonce failed: %v", err)
	}
	if bytes.Equal(ciphertext, ciphertextNonce2) {
		t.Errorf("different nonce must produce different ciphertext (nonce reuse detected!)")
	}

	// 5. Llave distinta -> ciphertext radicalmente diferente
	key2 := make([]byte, 32)
	copy(key2, key)
	key2[0] ^= 0xFF

	ciphertextKey2, err := enc.Encrypt(plaintext, key2, nonce)
	if err != nil {
		t.Fatalf("Encrypt with different key failed: %v", err)
	}
	if bytes.Equal(ciphertext, ciphertextKey2) {
		t.Errorf("different key must produce different ciphertext")
	}
}

func TestAESGCMEncryption_ValidationErrors(t *testing.T) {
	enc := NewAESGCMEncryptor()

	validKey := make([]byte, 32)
	validNonce := make([]byte, 12)
	plaintext := []byte("test payload")

	// 1. Llave con longitud inválida (16 bytes = AES-128, no AES-256)
	shortKey := make([]byte, 16)
	if _, err := enc.Encrypt(plaintext, shortKey, validNonce); !errors.Is(err, ErrInvalidKeyLength) {
		t.Errorf("expected ErrInvalidKeyLength for 16-byte key, got %v", err)
	}

	// 2. Llave vacía
	if _, err := enc.Encrypt(plaintext, []byte{}, validNonce); !errors.Is(err, ErrInvalidKeyLength) {
		t.Errorf("expected ErrInvalidKeyLength for empty key, got %v", err)
	}

	// 3. Nonce con longitud inválida (11 bytes)
	shortNonce := make([]byte, 11)
	if _, err := enc.Encrypt(plaintext, validKey, shortNonce); !errors.Is(err, ErrInvalidNonceLength) {
		t.Errorf("expected ErrInvalidNonceLength for 11-byte nonce, got %v", err)
	}

	// 4. Nonce de 16 bytes (también inválido para GCM)
	longNonce := make([]byte, 16)
	if _, err := enc.Encrypt(plaintext, validKey, longNonce); !errors.Is(err, ErrInvalidNonceLength) {
		t.Errorf("expected ErrInvalidNonceLength for 16-byte nonce, got %v", err)
	}
}

func TestAESGCMEncryption_EmptyPlaintext(t *testing.T) {
	enc := NewAESGCMEncryptor()
	key := make([]byte, 32)
	nonce := make([]byte, 12)

	// Cifrado de plaintext vacío: solo debe aparecer el tag GCM de 16 bytes
	ciphertext, err := enc.Encrypt([]byte{}, key, nonce)
	if err != nil {
		t.Fatalf("Encrypt of empty plaintext failed: %v", err)
	}
	if len(ciphertext) != 16 {
		t.Errorf("expected 16-byte GCM tag for empty plaintext, got %d bytes", len(ciphertext))
	}
}

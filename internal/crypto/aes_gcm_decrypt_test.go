package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func newKeyNonce(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	return key, nonce
}

func TestAESGCMDecryptSuccess(t *testing.T) {
	key, nonce := newKeyNonce(t)
	plaintext := []byte(`[{"event_id":"EVT-001","type":"REGISTRO_NOTA","payload":{"grade":4.5}}]`)

	ciphertext, err := NewAESGCMEncryptor().Encrypt(plaintext, key, nonce)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := NewAESGCMDecryptor().Decrypt(ciphertext, key, nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("round-trip mismatch:\nwant %q\ngot  %q", plaintext, decrypted)
	}
}

func TestAESGCMDecryptTampered(t *testing.T) {
	key, nonce := newKeyNonce(t)
	ciphertext, err := NewAESGCMEncryptor().Encrypt([]byte("academic log"), key, nonce)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	dec := NewAESGCMDecryptor()

	// Un solo bit alterado en cada posición (ciphertext y tag) debe ser rechazado.
	for i := range ciphertext {
		tampered := bytes.Clone(ciphertext)
		tampered[i] ^= 0x01
		if _, err := dec.Decrypt(tampered, key, nonce); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("byte %d flipped: expected ErrAuthenticationFailed, got %v", i, err)
		}
	}

	wrongKey, wrongNonce := newKeyNonce(t)
	if _, err := dec.Decrypt(ciphertext, wrongKey, nonce); !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("wrong key: expected ErrAuthenticationFailed, got %v", err)
	}
	if _, err := dec.Decrypt(ciphertext, key, wrongNonce); !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("wrong nonce: expected ErrAuthenticationFailed, got %v", err)
	}
	if _, err := dec.Decrypt(ciphertext[:10], key, nonce); !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("truncated ciphertext: expected ErrAuthenticationFailed, got %v", err)
	}
}

func TestAESGCMDecryptInvalidInputs(t *testing.T) {
	key, nonce := newKeyNonce(t)
	dec := NewAESGCMDecryptor()

	if _, err := dec.Decrypt([]byte("x"), key[:16], nonce); !errors.Is(err, ErrInvalidKeyLength) {
		t.Errorf("16-byte key: expected ErrInvalidKeyLength, got %v", err)
	}
	if _, err := dec.Decrypt([]byte("x"), key, nonce[:8]); !errors.Is(err, ErrInvalidNonceLength) {
		t.Errorf("8-byte nonce: expected ErrInvalidNonceLength, got %v", err)
	}
}

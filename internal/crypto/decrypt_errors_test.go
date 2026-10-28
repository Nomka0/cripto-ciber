package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestTamperingDetection(t *testing.T) {
	key, nonce := newKeyNonce(t)
	plaintext := []byte(`[{"event_id":"EVT-001","type":"MODIFICACION_NOTA","payload":{"old":3.2,"new":4.8}}]`)

	ciphertext, err := NewAESGCMEncryptor().Encrypt(plaintext, key, nonce)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	flipBit := func(b []byte) []byte {
		c := bytes.Clone(b)
		c[0] ^= 0x01
		return c
	}

	cases := []struct {
		name                   string
		ciphertext, key, nonce []byte
	}{
		{"tampered ciphertext", flipBit(ciphertext), key, nonce},
		{"wrong key", ciphertext, flipBit(key), nonce},
		{"modified nonce", ciphertext, key, flipBit(nonce)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SafeDecrypt(tc.ciphertext, tc.key, tc.nonce)
			if !errors.Is(err, ErrAuthenticationFailed) {
				t.Errorf("expected ErrAuthenticationFailed, got %v", err)
			}
			if got != nil {
				t.Errorf("plaintext leaked on failure: %q", got)
			}
		})
	}

	t.Run("valid inputs", func(t *testing.T) {
		got, err := SafeDecrypt(ciphertext, key, nonce)
		if err != nil {
			t.Fatalf("SafeDecrypt failed: %v", err)
		}
		if !bytes.Equal(plaintext, got) {
			t.Errorf("round-trip mismatch: want %q, got %q", plaintext, got)
		}
	})
}

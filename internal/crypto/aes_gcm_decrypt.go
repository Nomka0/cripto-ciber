package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// ErrAuthenticationFailed se retorna cuando gcm.Open rechaza el authentication tag:
// el ciphertext, el tag, la llave o el nonce fueron alterados o no corresponden.
var ErrAuthenticationFailed = errors.New("cipher authentication tag mismatch: data tampered or corrupted")

// SymmetricDecryptor define el contrato de descifrado simétrico autenticado (AEAD).
type SymmetricDecryptor interface {
	Decrypt(ciphertext, key, nonce []byte) ([]byte, error)
}

// AESGCMDecryptor implementa descifrado AES-256-GCM, inverso de AESGCMEncryptor.
type AESGCMDecryptor struct{}

// NewAESGCMDecryptor retorna una nueva instancia lista de AESGCMDecryptor.
func NewAESGCMDecryptor() *AESGCMDecryptor {
	return &AESGCMDecryptor{}
}

// Decrypt verifica el authentication tag (16 bytes finales del ciphertext) y,
// solo si es válido, retorna el plaintext original. Nunca entrega bytes parciales.
func (d *AESGCMDecryptor) Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM AEAD: %w", err)
	}

	if len(nonce) != gcm.NonceSize() { // 12 bytes
		return nil, ErrInvalidNonceLength
	}

	// Open valida el tag antes de liberar el plaintext. AAD = nil, igual que en Encrypt.
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return plaintext, nil
}

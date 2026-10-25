package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

var (
	// ErrInvalidKeyLength se retorna cuando la llave no tiene exactamente 32 bytes (AES-256).
	ErrInvalidKeyLength = errors.New("key length must be 32 bytes for AES-256")

	// ErrInvalidNonceLength se retorna cuando el nonce no tiene exactamente 12 bytes (estándar GCM).
	ErrInvalidNonceLength = errors.New("nonce length must be 12 bytes for AES-GCM")
)

// SymmetricEncryptor define el contrato de cifrado simétrico autenticado (AEAD).
type SymmetricEncryptor interface {
	Encrypt(plaintext, key, nonce []byte) ([]byte, error)
}

// AESGCMEncryptor implementa cifrado AES-256-GCM (Galois/Counter Mode).
// Garantiza confidencialidad e integridad mediante el tag de autenticación GCM de 16 bytes.
type AESGCMEncryptor struct{}

// NewAESGCMEncryptor retorna una nueva instancia lista de AESGCMEncryptor.
func NewAESGCMEncryptor() *AESGCMEncryptor {
	return &AESGCMEncryptor{}
}

// Encrypt cifra el plaintext con AES-256-GCM usando la llave y nonce provistos.
//
// Reglas de seguridad:
//   - La llave debe tener exactamente 32 bytes (AES-256).
//   - El nonce debe tener exactamente 12 bytes (estándar GCM / RFC 5288).
//   - NUNCA reutilizar el mismo nonce con la misma llave; destruiría la autenticidad
//     y comprometería la confidencialidad por ruptura del keystream GCM.
//
// El ciphertext resultante tiene longitud len(plaintext) + 16 bytes,
// donde los 16 bytes finales corresponden al GCM authentication tag.
func (e *AESGCMEncryptor) Encrypt(plaintext, key, nonce []byte) ([]byte, error) {
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

	// Seal cifra el plaintext y anexa el authentication tag (16 bytes) al final del ciphertext.
	// No se utilizan datos adicionales autenticados (AAD = nil).
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

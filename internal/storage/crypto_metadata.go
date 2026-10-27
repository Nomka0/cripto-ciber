package storage

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	ExpectedKeyLength   = 32 // 256 bits para AES-256
	ExpectedNonceLength = 12 // 96 bits para AES-GCM
	ExpectedAuthTagSize = 16 // 128 bits de autenticación GCM
	DefaultAlgorithm    = "AES-256-GCM"
)

var (
	ErrInvalidKeyLength   = errors.New("invalid key length: must be exactly 32 bytes")
	ErrInvalidNonceLength = errors.New("invalid nonce length: must be exactly 12 bytes")
	ErrInvalidAlgorithm   = errors.New("unsupported or invalid algorithm")
)

type CryptoMetadataDTO struct {
	Algorithm   string    `json:"algorithm"`
	KeyHex      string    `json:"key_hex"`
	NonceHex    string    `json:"nonce_hex"`
	AuthTagSize int       `json:"auth_tag_size"`
	CreatedAt   time.Time `json:"created_at"`
}

// SaveCryptoMetadata serializa los insumos criptográficos en formato JSON con permisos 0600.
func SaveCryptoMetadata(path string, key, nonce []byte) error {
	if len(key) != ExpectedKeyLength {
		return ErrInvalidKeyLength
	}
	if len(nonce) != ExpectedNonceLength {
		return ErrInvalidNonceLength
	}

	dto := CryptoMetadataDTO{
		Algorithm:   DefaultAlgorithm,
		KeyHex:      hex.EncodeToString(key),
		NonceHex:    hex.EncodeToString(nonce),
		AuthTagSize: ExpectedAuthTagSize,
		CreatedAt:   time.Now().UTC(),
	}

	data, err := json.MarshalIndent(dto, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal crypto metadata: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// LoadCryptoMetadata lee y deserializa los insumos criptográficos validando tipos y tamaños.
func LoadCryptoMetadata(path string) ([]byte, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read crypto metadata file %s: %w", path, err)
	}

	var dto CryptoMetadataDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal crypto metadata: %w", err)
	}

	if dto.Algorithm != DefaultAlgorithm {
		return nil, nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidAlgorithm, DefaultAlgorithm, dto.Algorithm)
	}

	key, err := hex.DecodeString(dto.KeyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode key_hex: %w", err)
	}
	if len(key) != ExpectedKeyLength {
		return nil, nil, fmt.Errorf("%w: decoded %d bytes", ErrInvalidKeyLength, len(key))
	}

	nonce, err := hex.DecodeString(dto.NonceHex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode nonce_hex: %w", err)
	}
	if len(nonce) != ExpectedNonceLength {
		return nil, nil, fmt.Errorf("%w: decoded %d bytes", ErrInvalidNonceLength, len(nonce))
	}

	return key, nonce, nil
}

// SaveCiphertext persiste los bytes del ciphertext crudo en disco con permisos 0600.
func SaveCiphertext(path string, ciphertext []byte) error {
	return os.WriteFile(path, ciphertext, 0600)
}

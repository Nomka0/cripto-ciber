package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

var ErrNilReader = errors.New("reader cannot be nil")

// ComputeSHA256 calcula el digest SHA-256 de un slice de bytes y lo retorna en hexadecimal minúsculas.
func ComputeSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ComputeStreamSHA256 calcula el digest SHA-256 leyendo un stream (io.Reader) sin cargarlo completo en memoria.
func ComputeStreamSHA256(r io.Reader) (string, error) {
	if r == nil {
		return "", ErrNilReader
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// ComputePayloadHash combina la extracción del payload puro y el cálculo del digest SHA-256.
func ComputePayloadHash(payload interface{}) (string, error) {
	data, err := ExtractPayloadBytes(payload)
	if err != nil {
		return "", err
	}
	return ComputeSHA256(data), nil
}

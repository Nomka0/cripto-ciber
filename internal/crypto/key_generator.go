package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	AES256KeySize = 32 // 256 bits
	GCMNonceSize  = 12 // 96 bits
)

// GenerateRandomBytes genera N bytes criptográficamente seguros leyendo del CSPRNG del sistema operativo.
// Usa io.ReadFull para garantizar que se lean exactamente n bytes sin truncamiento silencioso.
func GenerateRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("requested byte count must be positive, got %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("crypto/rand entropy failure: %w", err)
	}
	return b, nil
}

// GenerateAES256Key genera una llave simétrica de 256 bits (32 bytes) apta para AES-256-GCM.
func GenerateAES256Key() ([]byte, error) {
	return GenerateRandomBytes(AES256KeySize)
}

// GenerateGCMNonce genera un nonce aleatorio de 96 bits (12 bytes) para AES-GCM.
// IMPORTANTE: Cada invocación debe generar un nonce único; nunca reutilizar con la misma llave.
func GenerateGCMNonce() ([]byte, error) {
	return GenerateRandomBytes(GCMNonceSize)
}

// KeyToHex codifica una llave o nonce binario a su representación hexadecimal en minúsculas.
// Útil para persistencia segura del material criptográfico en disco o logs de auditoría.
func KeyToHex(key []byte) string {
	return hex.EncodeToString(key)
}

// HexToKey decodifica una cadena hexadecimal de vuelta al slice de bytes original.
// Retorna error si la cadena no es hexadecimal válida o si está vacía.
func HexToKey(hexStr string) ([]byte, error) {
	if hexStr == "" {
		return nil, fmt.Errorf("hex string cannot be empty")
	}
	key, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key material: %w", err)
	}
	return key, nil
}

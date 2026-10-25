package crypto

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// EncryptionArtifacts encapsula el resultado del cifrado del log y todos los insumos
// necesarios para el posterior descifrado y auditoría forense.
type EncryptionArtifacts struct {
	Ciphertext     []byte    `json:"-"`               // Bytes del ciphertext (no serializado directamente)
	Key            []byte    `json:"key"`             // Llave AES-256 (32 bytes)
	Nonce          []byte    `json:"nonce"`           // Nonce GCM (12 bytes)
	Algorithm      string    `json:"algorithm"`       // "AES-256-GCM"
	PlaintextSize  int64     `json:"plaintext_size"`  // Tamaño original en bytes
	CiphertextSize int64     `json:"ciphertext_size"` // Tamaño cifrado (plaintext + 16 tag)
	EncryptedAt    time.Time `json:"encrypted_at"`    // Marca temporal UTC del cifrado
}

// EncryptLogFile lee el log original en texto claro desde inputLogPath, genera
// material criptográfico fresco (llave AES-256 y nonce GCM de 12 bytes) y
// cifra el contenido completo con AES-256-GCM.
//
// Cada invocación genera nueva llave y nonce —nunca reutiliza material criptográfico.
func EncryptLogFile(inputLogPath string) (*EncryptionArtifacts, error) {
	cleanPath := strings.TrimSpace(inputLogPath)
	if cleanPath == "" {
		return nil, ErrEmptyFilePath
	}

	// 1. Leer los bytes del log en texto claro
	plaintext, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read plaintext log file %s: %w", cleanPath, err)
	}

	// 2. Generar llave AES-256 fresca mediante CSPRNG del SO
	key, err := GenerateAES256Key()
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES-256 key: %w", err)
	}

	// 3. Generar nonce GCM de 96 bits fresco — nunca reutilizar con la misma llave
	nonce, err := GenerateGCMNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate GCM nonce: %w", err)
	}

	// 4. Cifrar con AES-256-GCM
	enc := NewAESGCMEncryptor()
	ciphertext, err := enc.Encrypt(plaintext, key, nonce)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM encryption failed: %w", err)
	}

	// 5. Construir y retornar el paquete de artefactos
	return &EncryptionArtifacts{
		Ciphertext:     ciphertext,
		Key:            key,
		Nonce:          nonce,
		Algorithm:      "AES-256-GCM",
		PlaintextSize:  int64(len(plaintext)),
		CiphertextSize: int64(len(ciphertext)),
		EncryptedAt:    time.Now().UTC(),
	}, nil
}

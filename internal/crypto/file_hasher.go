package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// HashFile computa el digest SHA-256 de cualquier archivo en disco (texto plano o binario crudo cifrado)
// leyendo sus bytes directamente por streaming mediante io.Copy para optimizar el uso de memoria (O(1) RAM).
func HashFile(filePath string) (string, error) {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" {
		return "", ErrEmptyFilePath
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat file %s: %w", cleanPath, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%w: %s is a directory", ErrNotRegularFile, cleanPath)
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %w", cleanPath, err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to compute hash stream for file %s: %w", cleanPath, err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// SaveHashToFile persiste el hash SHA-256 en disco de manera segura y desacoplada.
// Conforme a las reglas de seguridad, almacena única y exclusivamente el digest hexadecimal,
// sin incluir material de llaves simétricas, vectores de inicialización ni datos del ciphertext.
func SaveHashToFile(hash, hashOutputPath string) error {
	cleanHash := strings.ToLower(strings.TrimSpace(hash))
	if cleanHash == "" {
		return errors.New("hash cannot be empty")
	}
	if len(cleanHash) != 64 {
		return fmt.Errorf("%w: expected 64 hex characters, got %d", ErrInvalidDigestLength, len(cleanHash))
	}

	cleanOutputPath := strings.TrimSpace(hashOutputPath)
	if cleanOutputPath == "" {
		return ErrEmptyFilePath
	}

	parentDir := filepath.Dir(cleanOutputPath)
	if parentDir != "" && parentDir != "." {
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for hash output: %w", err)
		}
	}

	if err := os.WriteFile(cleanOutputPath, []byte(cleanHash), 0644); err != nil {
		return fmt.Errorf("failed to write hash file %s: %w", cleanOutputPath, err)
	}

	return nil
}

// ComputeAndPersistEncryptedLogHash calcula el hash del ciphertext y lo persiste en disco.
// Corresponde al Paso 7 del taller: cálculo y persistencia desacoplada del hash del artefacto cifrado.
func ComputeAndPersistEncryptedLogHash(cipherPath, hashOutputPath string) (string, error) {
	hash, err := HashFile(cipherPath)
	if err != nil {
		return "", err
	}
	if err := SaveHashToFile(hash, hashOutputPath); err != nil {
		return "", err
	}
	return hash, nil
}

// ComputeAndPersistPlaintextLogHash calcula el hash del log original en texto claro y lo persiste en disco.
// Corresponde al Paso 5 del taller.
func ComputeAndPersistPlaintextLogHash(plainPath, hashOutputPath string) (string, error) {
	hash, err := HashFile(plainPath)
	if err != nil {
		return "", err
	}
	if err := SaveHashToFile(hash, hashOutputPath); err != nil {
		return "", err
	}
	return hash, nil
}

// ComputeDecryptedLogHash calcula el hash del log descifrado para la auditoría de integridad final.
// Corresponde al Paso 9 del taller de criptografía.
func ComputeDecryptedLogHash(decryptedLogPath string) (string, error) {
	return HashFile(decryptedLogPath)
}

// ComputeBytesHash calcula el digest SHA-256 directamente desde un buffer en memoria (data []byte),
// en caso de que el orquestador mantenga el log descifrado en RAM antes de escribir a disco.
func ComputeBytesHash(data []byte) string {
	return ComputeSHA256(data)
}


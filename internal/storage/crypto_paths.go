package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Nombres canónicos de los artefactos del ciclo de vida criptográfico.
// Garantizan la separación física e independencia entre el log original,
// el log cifrado en reposo y los insumos criptográficos requeridos para su descifrado.
const (
	// DefaultOutputDir es el directorio base estándar para la persistencia de artefactos.
	DefaultOutputDir = "output"

	// PlaintextLogFilename es el artefacto del Paso 4: Log consolidado en texto claro.
	PlaintextLogFilename = "academic_log.json"

	// PlaintextLogHashFilename es el artefacto del Paso 5: Testigo criptográfico SHA-256 del log en claro.
	PlaintextLogHashFilename = "academic_log.json.sha256"

	// EncryptedLogFilename es el artefacto del Paso 6: Log cifrado en reposo (AES-256-GCM binario).
	EncryptedLogFilename = "academic_log.enc"

	// CryptoMetadataFilename es el artefacto del Paso 6: Insumos criptográficos (llave, nonce, algoritmo).
	// Reside como un archivo físicamente desacoplado del ciphertext para cumplir con
	// el principio de separación de privilegios y aislamiento de secretos.
	CryptoMetadataFilename = "crypto_metadata.json"

	// EncryptedLogHashFilename es el artefacto del Paso 7: Testigo criptográfico SHA-256 del log cifrado.
	EncryptedLogHashFilename = "academic_log.enc.sha256"

	// DecryptedLogFilename es el artefacto del Paso 8: Log recuperado tras descifrado autenticado.
	DecryptedLogFilename = "academic_log_decrypted.json"

	// DecryptedLogHashFilename es el artefacto del Paso 9: Testigo criptográfico SHA-256 del log descifrado.
	DecryptedLogHashFilename = "academic_log_decrypted.sha256"

	// RestrictedDirPerms define los permisos del sistema de archivos requeridos para el directorio
	// de almacenamiento (0700: lectura, escritura y ejecución exclusiva para el propietario).
	// Aplica el principio de mínimo privilegio en reposo para prevenir que otros usuarios
	// del host accedan a los artefactos o insumos criptográficos.
	RestrictedDirPerms os.FileMode = 0700
)

var (
	// ErrPathIsFile se produce cuando la ruta especificada para el directorio ya existe como un archivo regular.
	ErrPathIsFile = errors.New("specified path exists and is not a directory")
)

// resolveBaseDir normaliza y limpia la ruta del directorio base.
// Si no se especifica ninguna ruta (cadena vacía o solo espacios),
// retorna el directorio canónico por defecto DefaultOutputDir ("output").
func resolveBaseDir(baseDir string) string {
	trimmed := strings.TrimSpace(baseDir)
	if trimmed == "" {
		return DefaultOutputDir
	}
	return filepath.Clean(trimmed)
}

// GetEncryptedLogPath retorna la ruta canónica y normalizada del log cifrado (academic_log.enc).
// Este artefacto contiene exclusivamente los bytes crudos resultantes del cifrado AES-256-GCM.
func GetEncryptedLogPath(baseDir string) string {
	return filepath.Join(resolveBaseDir(baseDir), EncryptedLogFilename)
}

// GetCryptoMetadataPath retorna la ruta canónica y normalizada de los insumos criptográficos (crypto_metadata.json).
// Mantener esta ruta físicamente separada del ciphertext (academic_log.enc) asegura que los secretos
// y parámetros (llave simétrica, nonce, metadata) no se almacenen junto a los datos protegidos.
func GetCryptoMetadataPath(baseDir string) string {
	return filepath.Join(resolveBaseDir(baseDir), CryptoMetadataFilename)
}

// GetPlaintextLogPath retorna la ruta canónica del log consolidado original en claro (academic_log.json).
func GetPlaintextLogPath(baseDir string) string {
	return filepath.Join(resolveBaseDir(baseDir), PlaintextLogFilename)
}

// GetPlaintextLogHashPath retorna la ruta canónica del testigo SHA-256 del log en claro (academic_log.json.sha256).
func GetPlaintextLogHashPath(baseDir string) string {
	return filepath.Join(resolveBaseDir(baseDir), PlaintextLogHashFilename)
}

// GetEncryptedLogHashPath retorna la ruta canónica del testigo SHA-256 del log cifrado (academic_log.enc.sha256).
func GetEncryptedLogHashPath(baseDir string) string {
	return filepath.Join(resolveBaseDir(baseDir), EncryptedLogHashFilename)
}

// GetDecryptedLogPath retorna la ruta canónica del log recuperado tras el descifrado (academic_log_decrypted.json).
func GetDecryptedLogPath(baseDir string) string {
	return filepath.Join(resolveBaseDir(baseDir), DecryptedLogFilename)
}

// GetDecryptedLogHashPath retorna la ruta canónica del testigo SHA-256 del log descifrado (academic_log_decrypted.sha256).
func GetDecryptedLogHashPath(baseDir string) string {
	return filepath.Join(resolveBaseDir(baseDir), DecryptedLogHashFilename)
}

// EnsureOutputDirectory valida o crea el directorio de salida asegurando permisos restrictivos (0700).
// Si el directorio no existe, lo crea recursivamente con permisos restringidos.
// Si ya existe, valida que sea efectivamente un directorio y no un archivo.
func EnsureOutputDirectory(dir string) error {
	resolvedDir := resolveBaseDir(dir)

	info, err := os.Stat(resolvedDir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(resolvedDir, RestrictedDirPerms); mkErr != nil {
				return fmt.Errorf("failed to create secure directory %s: %w", resolvedDir, mkErr)
			}
			return nil
		}
		return fmt.Errorf("failed to inspect directory %s: %w", resolvedDir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%w: %s", ErrPathIsFile, resolvedDir)
	}

	return nil
}

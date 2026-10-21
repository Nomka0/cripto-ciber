package crypto

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrEmptyFilePath se retorna cuando la ruta del archivo provista está vacía o solo contiene espacios.
	ErrEmptyFilePath = errors.New("file path cannot be empty")

	// ErrNotRegularFile se retorna cuando la ruta apunta a un directorio u otro artefacto no regular.
	ErrNotRegularFile = errors.New("target path is not a regular file")

	// ErrInvalidDigestFormat se retorna cuando el contenido de un archivo testigo no respeta el estándar coreutils.
	ErrInvalidDigestFormat = errors.New("invalid coreutils digest format")

	// ErrInvalidDigestLength se retorna cuando el digest extraído no cuenta con 64 caracteres hexadecimales.
	ErrInvalidDigestLength = errors.New("invalid sha256 digest length (expected 64 hex characters)")
)

// FileDigestResult almacena el resultado en memoria del hashing de un archivo
// y los metadatos de persistencia del testigo criptográfico generado en disco.
type FileDigestResult struct {
	TargetFilePath string `json:"target_file_path"` // Ruta física al archivo evaluado
	Filename       string `json:"filename"`         // Nombre base del archivo (ej. academic_log.json)
	Digest         string `json:"digest"`           // Hash SHA-256 en hexadecimal minúsculas (64 caracteres)
	DigestFilePath string `json:"digest_file_path"` // Ruta donde se persistió el archivo testigo (.sha256)
	Algorithm      string `json:"algorithm"`        // Algoritmo criptográfico utilizado ("SHA-256")
}

// GlobalHasher define el contrato para el cálculo y persistencia de digests globales
// en las distintas etapas del ciclo de vida del log (Pasos 5, 7 y 9).
type GlobalHasher interface {
	// HashFile calcula el digest SHA-256 de un archivo en disco mediante streaming.
	HashFile(filePath string) (string, error)

	// HashAndPersist calcula el digest y lo persiste en formato GNU/BSD coreutils (<hash>  <filename>).
	HashAndPersist(filePath string, customDigestPath ...string) (FileDigestResult, error)

	// HashPlaintextLog ejecuta el flujo del Paso 5 (academic_log.json -> academic_log.json.sha256).
	HashPlaintextLog(filePath string, customDigestPath ...string) (FileDigestResult, error)

	// HashEncryptedLog ejecuta el flujo del Paso 7 (academic_log.enc -> academic_log.enc.sha256).
	HashEncryptedLog(filePath string, customDigestPath ...string) (FileDigestResult, error)

	// HashDecryptedLog ejecuta el flujo del Paso 9 (academic_log_decrypted.json -> digest en memoria y opcional .sha256).
	HashDecryptedLog(filePath string, persist bool, customDigestPath ...string) (FileDigestResult, error)

	// VerifyFileAgainstDigestFile compara el archivo en disco contra el testigo .sha256.
	VerifyFileAgainstDigestFile(filePath, digestFilePath string) (bool, string, error)
}

// DefaultGlobalHasher es la implementación estándar de GlobalHasher.
type DefaultGlobalHasher struct{}

// NewGlobalHasher retorna una nueva instancia de GlobalHasher lista para operar.
func NewGlobalHasher() GlobalHasher {
	return &DefaultGlobalHasher{}
}

// HashFile calcula el digest SHA-256 de un archivo físico en disco leyendo sus bytes
// directamente mediante streaming (io.Copy hacia el hasher nativo).
func (h *DefaultGlobalHasher) HashFile(filePath string) (string, error) {
	return ComputeFileSHA256(filePath)
}

// HashAndPersist calcula el digest SHA-256 por streaming y lo almacena desacoplado en disco.
func (h *DefaultGlobalHasher) HashAndPersist(filePath string, customDigestPath ...string) (FileDigestResult, error) {
	return HashAndPersistFileSHA256(filePath, customDigestPath...)
}

// HashPlaintextLog atiende el Paso 5 del taller: calcula el hash del log original y lo persiste en disco.
func (h *DefaultGlobalHasher) HashPlaintextLog(filePath string, customDigestPath ...string) (FileDigestResult, error) {
	return HashAndPersistFileSHA256(filePath, customDigestPath...)
}

// HashEncryptedLog atiende el Paso 7 del taller: calcula el hash del log cifrado y lo persiste en disco.
func (h *DefaultGlobalHasher) HashEncryptedLog(filePath string, customDigestPath ...string) (FileDigestResult, error) {
	return HashAndPersistFileSHA256(filePath, customDigestPath...)
}

// HashDecryptedLog atiende el Paso 9 del taller: calcula el hash del log recuperado tras descifrado.
// Retorna el digest en memoria para verificación forense, y opcionalmente lo persiste si persist=true.
func (h *DefaultGlobalHasher) HashDecryptedLog(filePath string, persist bool, customDigestPath ...string) (FileDigestResult, error) {
	if persist {
		return HashAndPersistFileSHA256(filePath, customDigestPath...)
	}

	digest, err := ComputeFileSHA256(filePath)
	if err != nil {
		return FileDigestResult{}, err
	}

	return FileDigestResult{
		TargetFilePath: filePath,
		Filename:       filepath.Base(filePath),
		Digest:         digest,
		DigestFilePath: "",
		Algorithm:      "SHA-256",
	}, nil
}

// VerifyFileAgainstDigestFile comprueba si el archivo físico actual coincide con el digest almacenado en el archivo testigo.
func (h *DefaultGlobalHasher) VerifyFileAgainstDigestFile(filePath, digestFilePath string) (bool, string, error) {
	return VerifyFileAgainstDigestFile(filePath, digestFilePath)
}

// ComputeFileSHA256 abre el archivo indicado y computa su hash SHA-256 mediante streaming con io.Copy.
func ComputeFileSHA256(filePath string) (string, error) {
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

	return ComputeStreamSHA256(file)
}

// HashAndPersistFileSHA256 calcula el digest de filePath por streaming y escribe el archivo testigo en disco
// respetando el estándar BSD/GNU coreutils ("<hash>  <filename>\n").
func HashAndPersistFileSHA256(filePath string, customDigestPath ...string) (FileDigestResult, error) {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" {
		return FileDigestResult{}, ErrEmptyFilePath
	}

	digest, err := ComputeFileSHA256(cleanPath)
	if err != nil {
		return FileDigestResult{}, err
	}

	filename := filepath.Base(cleanPath)

	digestPath := cleanPath + ".sha256"
	if len(customDigestPath) > 0 && strings.TrimSpace(customDigestPath[0]) != "" {
		digestPath = strings.TrimSpace(customDigestPath[0])
	}

	parentDir := filepath.Dir(digestPath)
	if parentDir != "" && parentDir != "." {
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return FileDigestResult{}, fmt.Errorf("failed to create directory for digest file: %w", err)
		}
	}

	content := FormatCoreutilsDigest(digest, filename)
	if err := os.WriteFile(digestPath, []byte(content), 0644); err != nil {
		return FileDigestResult{}, fmt.Errorf("failed to persist digest file %s: %w", digestPath, err)
	}

	return FileDigestResult{
		TargetFilePath: cleanPath,
		Filename:       filename,
		Digest:         digest,
		DigestFilePath: digestPath,
		Algorithm:      "SHA-256",
	}, nil
}

// FormatCoreutilsDigest genera una línea en formato estándar BSD/GNU coreutils sha256sum:
// "<hash>  <filename>\n" utilizando exactamente dos espacios como delimitador.
func FormatCoreutilsDigest(digest, filename string) string {
	cleanDigest := strings.ToLower(strings.TrimSpace(digest))
	cleanFilename := filepath.Base(strings.TrimSpace(filename))
	return fmt.Sprintf("%s  %s\n", cleanDigest, cleanFilename)
}

// ParseCoreutilsDigest analiza una o más líneas con formato coreutils y extrae el hash y el nombre de archivo.
// Soporta tanto delimitador de texto estándar ("  ") como delimitador de modo binario (" *").
func ParseCoreutilsDigest(content string) (digest string, filename string, err error) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return "", "", ErrInvalidDigestFormat
	}

	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	var line string
	for scanner.Scan() {
		l := strings.TrimSpace(scanner.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			line = l
			break
		}
	}

	if line == "" {
		return "", "", ErrInvalidDigestFormat
	}

	var hashPart, filePart string
	if parts := strings.SplitN(line, "  ", 2); len(parts) == 2 {
		hashPart = parts[0]
		filePart = parts[1]
	} else if parts := strings.SplitN(line, " *", 2); len(parts) == 2 {
		hashPart = parts[0]
		filePart = parts[1]
	} else if parts := strings.SplitN(line, " ", 2); len(parts) == 2 {
		hashPart = parts[0]
		filePart = parts[1]
	} else {
		return "", "", ErrInvalidDigestFormat
	}

	hashPart = strings.ToLower(strings.TrimSpace(hashPart))
	filePart = strings.TrimSpace(filePart)

	if len(hashPart) != 64 {
		return "", "", fmt.Errorf("%w: got length %d", ErrInvalidDigestLength, len(hashPart))
	}

	for _, c := range hashPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", "", fmt.Errorf("%w: non-hex character '%c'", ErrInvalidDigestFormat, c)
		}
	}

	if filePart == "" {
		return "", "", ErrInvalidDigestFormat
	}

	return hashPart, filePart, nil
}

// VerifyFileAgainstDigestFile lee el archivo testigo en digestFilePath, extrae el hash esperado
// y lo compara en tiempo constante contra el hash recién computado del archivo filePath.
// Retorna (coincide, hashCalculado, error).
func VerifyFileAgainstDigestFile(filePath, digestFilePath string) (bool, string, error) {
	rawDigest, err := os.ReadFile(digestFilePath)
	if err != nil {
		return false, "", fmt.Errorf("failed to read digest file %s: %w", digestFilePath, err)
	}

	expectedDigest, _, err := ParseCoreutilsDigest(string(rawDigest))
	if err != nil {
		return false, "", fmt.Errorf("malformed digest file %s: %w", digestFilePath, err)
	}

	computedDigest, err := ComputeFileSHA256(filePath)
	if err != nil {
		return false, "", fmt.Errorf("failed to compute hash for target file %s: %w", filePath, err)
	}

	matches := CompareDigests(computedDigest, expectedDigest)
	return matches, computedDigest, nil
}

// CompareDigests efectúa una comparación en tiempo constante (subtle.ConstantTimeCompare)
// entre dos digests hexadecimales, previniendo ataques de canal lateral basados en tiempo (timing attacks).
func CompareDigests(digestA, digestB string) bool {
	a := strings.ToLower(strings.TrimSpace(digestA))
	b := strings.ToLower(strings.TrimSpace(digestB))

	if len(a) != len(b) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

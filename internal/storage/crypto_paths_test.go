package storage

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCryptoPaths(t *testing.T) {
	t.Run("CanonicalPathResolution", func(t *testing.T) {
		tempDir := t.TempDir()

		encPath := GetEncryptedLogPath(tempDir)
		expectedEncPath := filepath.Join(tempDir, EncryptedLogFilename)
		if encPath != expectedEncPath {
			t.Errorf("GetEncryptedLogPath mismatch: expected %q, got %q", expectedEncPath, encPath)
		}

		metaPath := GetCryptoMetadataPath(tempDir)
		expectedMetaPath := filepath.Join(tempDir, CryptoMetadataFilename)
		if metaPath != expectedMetaPath {
			t.Errorf("GetCryptoMetadataPath mismatch: expected %q, got %q", expectedMetaPath, metaPath)
		}

		// Validar que los artefactos sean físicamente independientes
		if encPath == metaPath {
			t.Fatal("encrypted log path and crypto metadata path must not be identical")
		}

		if filepath.Base(encPath) != "academic_log.enc" {
			t.Errorf("expected base name 'academic_log.enc', got %q", filepath.Base(encPath))
		}
		if filepath.Base(metaPath) != "crypto_metadata.json" {
			t.Errorf("expected base name 'crypto_metadata.json', got %q", filepath.Base(metaPath))
		}
	})

	t.Run("DefaultOutputDirectoryResolution", func(t *testing.T) {
		// Al pasar cadena vacía, debe resolver contra DefaultOutputDir ("output")
		encPath := GetEncryptedLogPath("")
		expectedEncPath := filepath.Join(DefaultOutputDir, EncryptedLogFilename)
		if encPath != expectedEncPath {
			t.Errorf("default GetEncryptedLogPath mismatch: expected %q, got %q", expectedEncPath, encPath)
		}

		metaPath := GetCryptoMetadataPath("   ")
		expectedMetaPath := filepath.Join(DefaultOutputDir, CryptoMetadataFilename)
		if metaPath != expectedMetaPath {
			t.Errorf("default GetCryptoMetadataPath mismatch: expected %q, got %q", expectedMetaPath, metaPath)
		}
	})

	t.Run("AllArtifactPathsConvention", func(t *testing.T) {
		baseDir := "/secure/audit"

		tests := []struct {
			name     string
			actual   string
			expected string
		}{
			{"PlaintextLog", GetPlaintextLogPath(baseDir), filepath.Join(baseDir, "academic_log.json")},
			{"PlaintextLogHash", GetPlaintextLogHashPath(baseDir), filepath.Join(baseDir, "academic_log.json.sha256")},
			{"EncryptedLog", GetEncryptedLogPath(baseDir), filepath.Join(baseDir, "academic_log.enc")},
			{"CryptoMetadata", GetCryptoMetadataPath(baseDir), filepath.Join(baseDir, "crypto_metadata.json")},
			{"EncryptedLogHash", GetEncryptedLogHashPath(baseDir), filepath.Join(baseDir, "academic_log.enc.sha256")},
			{"DecryptedLog", GetDecryptedLogPath(baseDir), filepath.Join(baseDir, "academic_log_decrypted.json")},
			{"DecryptedLogHash", GetDecryptedLogHashPath(baseDir), filepath.Join(baseDir, "academic_log_decrypted.sha256")},
		}

		for _, tc := range tests {
			if tc.actual != tc.expected {
				t.Errorf("%s path mismatch: expected %q, got %q", tc.name, tc.expected, tc.actual)
			}
		}
	})

	t.Run("EnsureOutputDirectory_CreationAndPermissions", func(t *testing.T) {
		tempDir := t.TempDir()
		targetDir := filepath.Join(tempDir, "nested", "secure_output")

		if err := EnsureOutputDirectory(targetDir); err != nil {
			t.Fatalf("EnsureOutputDirectory failed: %v", err)
		}

		info, err := os.Stat(targetDir)
		if err != nil {
			t.Fatalf("failed to stat created directory: %v", err)
		}

		if !info.IsDir() {
			t.Fatalf("expected path %s to be a directory", targetDir)
		}

		// En sistemas tipo POSIX (Linux/macOS), verificar que los permisos sean exactamente 0700.
		// En Windows, el sistema de permisos de archivos de os.FileMode no mapea los bits POSIX directamente.
		if runtime.GOOS != "windows" {
			if perm := info.Mode().Perm(); perm != RestrictedDirPerms {
				t.Errorf("expected permissions %04o, got %04o", RestrictedDirPerms, perm)
			}
		}
	})

	t.Run("EnsureOutputDirectory_Idempotency", func(t *testing.T) {
		tempDir := t.TempDir()

		// Llamada inicial
		if err := EnsureOutputDirectory(tempDir); err != nil {
			t.Fatalf("initial EnsureOutputDirectory failed: %v", err)
		}

		// Segunda llamada sobre directorio existente debe ser exitosa sin errores
		if err := EnsureOutputDirectory(tempDir); err != nil {
			t.Fatalf("idempotent EnsureOutputDirectory call failed: %v", err)
		}
	})

	t.Run("EnsureOutputDirectory_ErrorWhenPathIsFile", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "conflict_file.txt")

		if err := os.WriteFile(filePath, []byte("not a directory"), 0600); err != nil {
			t.Fatalf("failed to create dummy file: %v", err)
		}

		err := EnsureOutputDirectory(filePath)
		if err == nil {
			t.Fatal("expected error when trying to EnsureOutputDirectory on existing file, got nil")
		}

		if !errors.Is(err, ErrPathIsFile) {
			t.Errorf("expected error wrapping ErrPathIsFile, got: %v", err)
		}
	})

	t.Run("PhysicalSeparationGuarantee", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := EnsureOutputDirectory(tempDir); err != nil {
			t.Fatalf("EnsureOutputDirectory failed: %v", err)
		}

		encPath := GetEncryptedLogPath(tempDir)
		metaPath := GetCryptoMetadataPath(tempDir)

		// Simular escritura de artefactos independientes
		ciphertextData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
		metadataData := []byte(`{"algorithm":"AES-256-GCM","nonce":"12bytesnonce"}`)

		if err := os.WriteFile(encPath, ciphertextData, 0600); err != nil {
			t.Fatalf("failed to write encrypted log artifact: %v", err)
		}

		if err := os.WriteFile(metaPath, metadataData, 0600); err != nil {
			t.Fatalf("failed to write crypto metadata artifact: %v", err)
		}

		// Verificar que ambos archivos existan de forma independiente
		readEnc, err := os.ReadFile(encPath)
		if err != nil {
			t.Fatalf("failed to read encrypted log: %v", err)
		}
		if string(readEnc) != string(ciphertextData) {
			t.Errorf("ciphertext content mismatch: expected %v, got %v", ciphertextData, readEnc)
		}

		readMeta, err := os.ReadFile(metaPath)
		if err != nil {
			t.Fatalf("failed to read crypto metadata: %v", err)
		}
		if string(readMeta) != string(metadataData) {
			t.Errorf("metadata content mismatch: expected %s, got %s", string(metadataData), string(readMeta))
		}

		// Eliminar el archivo de metadatos no debe alterar la existencia ni contenido del ciphertext
		if err := os.Remove(metaPath); err != nil {
			t.Fatalf("failed to remove metadata file: %v", err)
		}

		if _, err := os.Stat(metaPath); !os.IsNotExist(err) {
			t.Errorf("expected metadata file to be deleted")
		}

		if _, err := os.Stat(encPath); err != nil {
			t.Errorf("encrypted log must remain intact after metadata removal: %v", err)
		}
	})
}

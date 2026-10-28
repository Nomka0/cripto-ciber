package crypto

import (
	"fmt"
	"os"

	"taller2-criptografia/internal/storage"
)

// RestoreDecryptedLogFile coordina el Paso 8: carga los insumos criptográficos y el log cifrado,
// ejecuta el descifrado autenticado y persiste el artefacto reconstruido en outputDecryptedPath.
//
// Si la autenticación falla no se escribe ningún archivo: el disco nunca recibe bytes no verificados.
// El archivo se crea con permisos 0600 (igual que el resto de artefactos sensibles); el propietario
// conserva lectura para el cálculo de hashes del Paso 9.
func RestoreDecryptedLogFile(encLogPath, metadataPath, outputDecryptedPath string) ([]byte, error) {
	key, nonce, err := storage.LoadCryptoMetadata(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load crypto metadata: %w", err)
	}

	ciphertext, err := os.ReadFile(encLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted log: %w", err)
	}

	plaintext, err := SafeDecrypt(ciphertext, key, nonce)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	if err := os.WriteFile(outputDecryptedPath, plaintext, 0600); err != nil {
		return nil, fmt.Errorf("failed to write decrypted log file: %w", err)
	}
	return plaintext, nil
}

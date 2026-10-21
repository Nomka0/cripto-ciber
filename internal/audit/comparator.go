package audit

import (
	"crypto/subtle"
	"strings"
)

// IntegrityComparisonResult encapsula el resultado forense de la comparación
// entre el hash del artefacto original y el hash del artefacto descifrado.
type IntegrityComparisonResult struct {
	OriginalHash  string `json:"original_hash"`
	DecryptedHash string `json:"decrypted_hash"`
	Matches       bool   `json:"matches"`
}

// CompareHashes compara dos cadenas de hash en tiempo constante evitando timing attacks.
// Normaliza previamente las entradas eliminando espacios en blanco, newlines y convirtiendo a minúsculas.
func CompareHashes(originalHash, decryptedHash string) IntegrityComparisonResult {
	origClean := strings.TrimSpace(strings.ToLower(originalHash))
	decrClean := strings.TrimSpace(strings.ToLower(decryptedHash))

	origBytes := []byte(origClean)
	decrBytes := []byte(decrClean)

	// subtle.ConstantTimeCompare retorna 1 si los slices son idénticos en tiempo constante.
	// Si las longitudes difieren, retorna 0 de forma segura.
	matches := subtle.ConstantTimeCompare(origBytes, decrBytes) == 1

	return IntegrityComparisonResult{
		OriginalHash:  origClean,
		DecryptedHash: decrClean,
		Matches:       matches,
	}
}

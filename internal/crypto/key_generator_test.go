package crypto

import (
	"encoding/hex"
	"testing"
)

func TestKeyAndNonceGeneration(t *testing.T) {
	const iterations = 1000

	// -------------------------------------------------------
	// CRITERIO DE ÉXITO OBLIGATORIO:
	// Generar 1,000 llaves y 1,000 nonces, verificar que:
	// 1. Ninguna sea duplicada (unicidad estadística del CSPRNG)
	// 2. Las longitudes en bytes sean exactamente 32 y 12
	// -------------------------------------------------------
	seenKeys := make(map[string]bool, iterations)
	seenNonces := make(map[string]bool, iterations)

	for i := 0; i < iterations; i++ {
		// --- Llave AES-256 ---
		key, err := GenerateAES256Key()
		if err != nil {
			t.Fatalf("GenerateAES256Key failed at iteration %d: %v", i, err)
		}

		if len(key) != AES256KeySize {
			t.Errorf("key length mismatch at iteration %d: expected %d, got %d",
				i, AES256KeySize, len(key))
		}

		hexKey := hex.EncodeToString(key)
		if seenKeys[hexKey] {
			t.Fatalf("CRITICAL: duplicate key generated at iteration %d (CSPRNG failure)", i)
		}
		seenKeys[hexKey] = true

		// --- Nonce GCM ---
		nonce, err := GenerateGCMNonce()
		if err != nil {
			t.Fatalf("GenerateGCMNonce failed at iteration %d: %v", i, err)
		}

		if len(nonce) != GCMNonceSize {
			t.Errorf("nonce length mismatch at iteration %d: expected %d, got %d",
				i, GCMNonceSize, len(nonce))
		}

		hexNonce := hex.EncodeToString(nonce)
		if seenNonces[hexNonce] {
			t.Fatalf("CRITICAL: duplicate nonce generated at iteration %d (CSPRNG failure)", i)
		}
		seenNonces[hexNonce] = true
	}

	if len(seenKeys) != iterations {
		t.Errorf("expected %d unique keys, got %d", iterations, len(seenKeys))
	}
	if len(seenNonces) != iterations {
		t.Errorf("expected %d unique nonces, got %d", iterations, len(seenNonces))
	}
}

func TestGenerateRandomBytes_Lengths(t *testing.T) {
	sizes := []int{1, 12, 16, 32, 64, 128}
	for _, n := range sizes {
		b, err := GenerateRandomBytes(n)
		if err != nil {
			t.Errorf("GenerateRandomBytes(%d) failed: %v", n, err)
			continue
		}
		if len(b) != n {
			t.Errorf("expected %d bytes, got %d", n, len(b))
		}
	}
}

func TestGenerateRandomBytes_InvalidSize(t *testing.T) {
	if _, err := GenerateRandomBytes(0); err == nil {
		t.Errorf("expected error for 0 bytes, got nil")
	}
	if _, err := GenerateRandomBytes(-1); err == nil {
		t.Errorf("expected error for negative size, got nil")
	}
}

func TestHexEncodeDecodeRoundtrip(t *testing.T) {
	key, err := GenerateAES256Key()
	if err != nil {
		t.Fatalf("GenerateAES256Key failed: %v", err)
	}

	// Codificar a hex y recuperar
	hexStr := KeyToHex(key)
	if len(hexStr) != AES256KeySize*2 {
		t.Errorf("expected hex string of length %d, got %d", AES256KeySize*2, len(hexStr))
	}

	recovered, err := HexToKey(hexStr)
	if err != nil {
		t.Fatalf("HexToKey failed: %v", err)
	}
	if len(recovered) != AES256KeySize {
		t.Errorf("recovered key length mismatch: expected %d, got %d", AES256KeySize, len(recovered))
	}
	for i := range key {
		if key[i] != recovered[i] {
			t.Errorf("roundtrip mismatch at byte %d: original %02x, recovered %02x", i, key[i], recovered[i])
		}
	}

	// Nonce también
	nonce, _ := GenerateGCMNonce()
	hexNonce := KeyToHex(nonce)
	recoveredNonce, err := HexToKey(hexNonce)
	if err != nil {
		t.Fatalf("nonce HexToKey failed: %v", err)
	}
	if len(recoveredNonce) != GCMNonceSize {
		t.Errorf("recovered nonce length mismatch: expected %d, got %d", GCMNonceSize, len(recoveredNonce))
	}
}

func TestHexToKey_Errors(t *testing.T) {
	// Cadena vacía
	if _, err := HexToKey(""); err == nil {
		t.Errorf("expected error for empty hex string, got nil")
	}
	// Cadena no hexadecimal
	if _, err := HexToKey("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"); err == nil {
		t.Errorf("expected error for invalid hex string, got nil")
	}
	// Longitud impar (hex inválido)
	if _, err := HexToKey("abc"); err == nil {
		t.Errorf("expected error for odd-length hex string, got nil")
	}
}

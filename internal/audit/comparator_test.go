package audit

import (
	"testing"
)

func TestCompareHashes(t *testing.T) {
	const validHash1 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	const validHashDiffLast = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae"
	const shortHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015"

	tests := []struct {
		name          string
		orig          string
		decr          string
		wantMatch     bool
		expectedOrig  string
		expectedDecr  string
	}{
		{
			name:         "Caso Obligatorio 1: Hashes idénticos",
			orig:         validHash1,
			decr:         validHash1,
			wantMatch:    true,
			expectedOrig: validHash1,
			expectedDecr: validHash1,
		},
		{
			name:         "Caso Obligatorio 2: Hashes que difieren en el último carácter",
			orig:         validHash1,
			decr:         validHashDiffLast,
			wantMatch:    false,
			expectedOrig: validHash1,
			expectedDecr: validHashDiffLast,
		},
		{
			name:         "Caso Obligatorio 3: Hashes con longitudes distintas",
			orig:         validHash1,
			decr:         shortHash,
			wantMatch:    false,
			expectedOrig: validHash1,
			expectedDecr: shortHash,
		},
		{
			name:         "Normalización: Insensibilidad a mayúsculas y minúsculas",
			orig:         "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
			decr:         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			wantMatch:    true,
			expectedOrig: validHash1,
			expectedDecr: validHash1,
		},
		{
			name:         "Normalización: Eliminación de espacios en blanco y newlines",
			orig:         "  \n" + validHash1 + "  \r\n",
			decr:         "\t" + validHash1 + " ",
			wantMatch:    true,
			expectedOrig: validHash1,
			expectedDecr: validHash1,
		},
		{
			name:         "Diferencia en el primer carácter",
			orig:         "aa7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			decr:         validHash1,
			wantMatch:    false,
			expectedOrig: "aa7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			expectedDecr: validHash1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := CompareHashes(tc.orig, tc.decr)

			if res.Matches != tc.wantMatch {
				t.Errorf("Matches mismatch for %q: expected %v, got %v",
					tc.name, tc.wantMatch, res.Matches)
			}

			if res.OriginalHash != tc.expectedOrig {
				t.Errorf("OriginalHash mismatch: expected %q, got %q",
					tc.expectedOrig, res.OriginalHash)
			}

			if res.DecryptedHash != tc.expectedDecr {
				t.Errorf("DecryptedHash mismatch: expected %q, got %q",
					tc.expectedDecr, res.DecryptedHash)
			}
		})
	}
}

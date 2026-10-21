package generator

import (
	"strings"
	"testing"
)

func TestUUIDv4Generation(t *testing.T) {
	const count = 10_000
	seen := make(map[string]struct{}, count)

	for i := 0; i < count; i++ {
		uuid, err := GenerateUUIDv4()
		if err != nil {
			t.Fatalf("iteration %d: failed to generate UUIDv4: %v", i, err)
		}

		// Chequeo de colisión
		if _, exists := seen[uuid]; exists {
			t.Fatalf("collision detected at iteration %d: %s", i, uuid)
		}
		seen[uuid] = struct{}{}

		// Formato: 8-4-4-4-12 = 36 caracteres con 4 guiones
		if len(uuid) != 36 {
			t.Fatalf("invalid length %d for UUID: %s", len(uuid), uuid)
		}
		if uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
			t.Fatalf("invalid hyphen positions in UUID: %s", uuid)
		}

		// Versión 4: carácter en índice 14 debe ser '4'
		if uuid[14] != '4' {
			t.Fatalf("expected version 4 at index 14, got %c in %s", uuid[14], uuid)
		}

		// Variante RFC 4122: carácter en índice 19 debe ser '8', '9', 'a', o 'b'
		variantChar := uuid[19]
		if variantChar != '8' && variantChar != '9' && variantChar != 'a' && variantChar != 'b' {
			t.Fatalf("invalid RFC 4122 variant character %c at index 19 in %s", variantChar, uuid)
		}
	}
}

func TestSyntheticCatalogGenerators(t *testing.T) {
	studentUID := GenerateStudentUID()
	if !strings.HasPrefix(studentUID, "STU-") || len(studentUID) != 40 {
		t.Fatalf("unexpected format for student UID: %s", studentUID)
	}

	docUID := GenerateProfessorUID()
	if !strings.HasPrefix(docUID, "DOC-") || len(docUID) != 40 {
		t.Fatalf("unexpected format for doc UID: %s", docUID)
	}

	subUID := GenerateSubjectUID()
	if !strings.HasPrefix(subUID, "SUB-") || len(subUID) != 40 {
		t.Fatalf("unexpected format for sub UID: %s", subUID)
	}

	if len(DefaultSubjectCatalog) < 3 {
		t.Fatalf("expected default catalog items, got %d", len(DefaultSubjectCatalog))
	}
}

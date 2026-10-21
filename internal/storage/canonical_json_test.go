package storage

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"taller2-criptografia/internal/domain"
)

func buildSampleLog() *ConsolidatedAcademicLog {
	fixedTime := time.Date(2026, time.October, 20, 22, 0, 0, 0, time.UTC)
	log := NewConsolidatedAcademicLog("LOG-TEST-001", "AUDIT_SIMULATION")
	log.Metadata.CreatedAt = fixedTime

	regEvt, _ := domain.NewGradeRegistrationEvent("EVT-REG-00001", domain.GradeRegistrationPayload{
		StudentUID:   "STU-001",
		SubjectUID:   "SUB-750001C-CRIPTO",
		EvaluatorUID: "DOC-001",
		Grade:        4.5,
		Evaluation:   "Taller 1 & Taller 2 <Final>",
		Timestamp:    fixedTime.Add(-10 * time.Minute),
	})
	regEvt.PayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	modEvt, _ := domain.NewGradeModificationEvent("EVT-MOD-00002", domain.GradeModificationPayload{
		StudentUID:    "STU-001",
		SubjectUID:    "SUB-750001C-CRIPTO",
		ModifierUID:   "DOC-001",
		PreviousGrade: 4.5,
		NewGrade:      4.9,
		Reason:        "Revisión de notas: nota > 4.5 & corrección autorizada",
		Evaluation:    "Taller 1 & Taller 2 <Final>",
		Timestamp:     fixedTime,
	})
	modEvt.PayloadHash = "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"

	log.AddEvent(regEvt)
	log.AddEvent(modEvt)

	return log
}

func TestCanonicalDeterminism(t *testing.T) {
	log := buildSampleLog()

	const iterations = 100
	var firstBytes []byte
	var firstHash [32]byte

	for i := 0; i < iterations; i++ {
		data, err := MarshalCanonical(log)
		if err != nil {
			t.Fatalf("iteration %d: unexpected marshal error: %v", i, err)
		}

		hash := sha256.Sum256(data)

		if i == 0 {
			firstBytes = data
			firstHash = hash
			continue
		}

		if !bytes.Equal(firstBytes, data) {
			t.Fatalf("iteration %d: non-deterministic serialization detected (bytes mismatch)", i)
		}

		if firstHash != hash {
			t.Fatalf("iteration %d: SHA-256 hash mismatch: expected %x, got %x", i, firstHash, hash)
		}
	}
}

func TestCanonicalNoHTMLEscape(t *testing.T) {
	log := buildSampleLog()

	data, err := MarshalCanonical(log)
	if err != nil {
		t.Fatalf("unexpected error marshaling canonical log: %v", err)
	}

	// Verificar que <, >, & NO hayan sido reemplazados por secuencias Unicode \u003c, \u003e, \u0026
	content := string(data)
	if bytes.Contains(data, []byte(`\u003c`)) || bytes.Contains(data, []byte(`\u003e`)) || bytes.Contains(data, []byte(`\u0026`)) {
		t.Fatalf("canonical JSON contains HTML-escaped characters: %s", content)
	}

	if !bytes.Contains(data, []byte("<Final>")) {
		t.Fatalf("canonical JSON missing unescaped '<Final>'")
	}
	if !bytes.Contains(data, []byte("&")) {
		t.Fatalf("canonical JSON missing unescaped '&'")
	}
}

func TestFilePersistenceRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit_log.json")

	log := buildSampleLog()

	if err := SaveCanonicalLogToFile(filePath, log); err != nil {
		t.Fatalf("failed to save canonical log to file: %v", err)
	}

	loadedLog, err := LoadCanonicalLogFromFile(filePath)
	if err != nil {
		t.Fatalf("failed to load canonical log from file: %v", err)
	}

	if loadedLog.Metadata.LogID != log.Metadata.LogID {
		t.Errorf("expected LogID %s, got %s", log.Metadata.LogID, loadedLog.Metadata.LogID)
	}
	if loadedLog.Metadata.TotalEvents != 2 || len(loadedLog.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(loadedLog.Events))
	}

	// Reserializar el log cargado y comparar con el original
	originalBytes, err := MarshalCanonical(log)
	if err != nil {
		t.Fatalf("failed to marshal original: %v", err)
	}

	loadedBytes, err := MarshalCanonical(loadedLog)
	if err != nil {
		t.Fatalf("failed to marshal loaded: %v", err)
	}

	if !bytes.Equal(originalBytes, loadedBytes) {
		t.Fatal("serialized bytes of loaded log do not match original log bytes")
	}

	// Error al intentar guardar log nil
	if err := SaveCanonicalLogToFile(filePath, nil); err != ErrNilLog {
		t.Errorf("expected ErrNilLog, got %v", err)
	}

	// Error al intentar cargar archivo inexistente
	if _, err := LoadCanonicalLogFromFile(filepath.Join(tmpDir, "non_existent.json")); err == nil {
		t.Error("expected error loading non-existent file, got nil")
	}
}

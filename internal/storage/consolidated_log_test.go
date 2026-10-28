package storage

import (
	"path/filepath"
	"testing"
	"time"

	"taller2-criptografia/internal/domain"
)

func TestConsolidatedAcademicLog(t *testing.T) {
	payload := domain.GradeRegistrationPayload{
		StudentUID:   "STU-001",
		SubjectUID:   "SUB-001",
		EvaluatorUID: "DOC-001",
		Grade:        4.5,
		Evaluation:   "Taller 1",
		Timestamp:    time.Now().UTC(),
	}

	evt, err := domain.NewGradeRegistrationEvent("EVT-001", payload)
	if err != nil {
		t.Fatalf("failed to create event: %v", err)
	}

	log := NewConsolidatedAcademicLog([]domain.GenericEvent{evt})
	if log == nil {
		t.Fatal("expected non-nil log")
	}

	if log.TotalEvents != 1 {
		t.Errorf("expected TotalEvents 1, got %d", log.TotalEvents)
	}

	if len(log.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(log.Events))
	}

	if log.SchemaVersion != "1.0.0" {
		t.Errorf("expected SchemaVersion '1.0.0', got %s", log.SchemaVersion)
	}
}

func TestSaveAndLoadConsolidatedLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test_log.json")

	regPayload := domain.GradeRegistrationPayload{
		StudentUID:   "STU-001",
		SubjectUID:   "SUB-001",
		EvaluatorUID: "DOC-001",
		Grade:        4.5,
		Evaluation:   "Taller 1",
		Timestamp:    time.Now().UTC(),
	}
	regEvt, err := domain.NewGradeRegistrationEvent("EVT-REG-001", regPayload)
	if err != nil {
		t.Fatalf("failed to create registration event: %v", err)
	}
	regEvt.PayloadHash = "abcdef0123456789"

	modPayload := domain.GradeModificationPayload{
		StudentUID:    "STU-001",
		SubjectUID:    "SUB-001",
		ModifierUID:   "DOC-001",
		PreviousGrade: 4.5,
		NewGrade:      4.8,
		Reason:        "Revisión de reclamo presencial y ajuste en punto 3",
		Evaluation:    "Taller 1",
		Timestamp:     time.Now().UTC(),
	}
	modEvt, err := domain.NewGradeModificationEvent("EVT-MOD-001", modPayload)
	if err != nil {
		t.Fatalf("failed to create modification event: %v", err)
	}
	modEvt.PayloadHash = "1234567890abcdef"

	originalLog := NewConsolidatedAcademicLog([]domain.GenericEvent{regEvt, modEvt})

	if err := SaveConsolidatedLogToFile(logPath, originalLog); err != nil {
		t.Fatalf("SaveConsolidatedLogToFile failed: %v", err)
	}

	loadedLog, err := LoadConsolidatedLogFromFile(logPath)
	if err != nil {
		t.Fatalf("LoadConsolidatedLogFromFile failed: %v", err)
	}

	if loadedLog.TotalEvents != 2 {
		t.Errorf("expected 2 total events, got %d", loadedLog.TotalEvents)
	}
	if len(loadedLog.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(loadedLog.Events))
	}

	// Verificar tipos concretos recuperados
	if _, ok := loadedLog.Events[0].(*domain.GradeRegistrationEvent); !ok {
		t.Errorf("expected first event to be *domain.GradeRegistrationEvent, got %T", loadedLog.Events[0])
	}
	if _, ok := loadedLog.Events[1].(*domain.GradeModificationEvent); !ok {
		t.Errorf("expected second event to be *domain.GradeModificationEvent, got %T", loadedLog.Events[1])
	}
	if loadedLog.Events[0].GetPayloadHash() != "abcdef0123456789" {
		t.Errorf("expected payload hash preserved, got %s", loadedLog.Events[0].GetPayloadHash())
	}
}

func TestSaveConsolidatedLogToFile_Errors(t *testing.T) {
	if err := SaveConsolidatedLogToFile("/tmp/dummy.json", nil); err != ErrNilConsolidatedLog {
		t.Errorf("expected ErrNilConsolidatedLog, got %v", err)
	}
	if _, err := LoadConsolidatedLogFromFile("/nonexistent/file.json"); err == nil {
		t.Errorf("expected error reading nonexistent file")
	}
}


package storage

import (
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

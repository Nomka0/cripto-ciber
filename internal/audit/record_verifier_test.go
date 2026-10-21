package audit

import (
	"math/rand/v2"
	"testing"
	"time"

	"taller2-criptografia/internal/crypto"
	"taller2-criptografia/internal/domain"
	"taller2-criptografia/internal/generator"
	"taller2-criptografia/internal/storage"
)

func TestVerifyAllRecords(t *testing.T) {
	// Generar 100 eventos deterministas con semilla fija
	r := rand.New(rand.NewPCG(42, 1024))
	orch := generator.NewEventOrchestrator(nil, r)

	rawSequence, err := orch.GenerateSequence(100)
	if err != nil {
		t.Fatalf("failed to generate 100 events: %v", err)
	}

	events := make([]domain.GenericEvent, len(rawSequence))
	for i, raw := range rawSequence {
		evt, ok := raw.(domain.GenericEvent)
		if !ok {
			t.Fatalf("event at index %d does not implement domain.GenericEvent", i)
		}

		// Sellar criptográficamente cada evento con su payload_hash (Paso 3)
		if err := crypto.SignEventPayload(evt); err != nil {
			t.Fatalf("failed to sign event at index %d: %v", i, err)
		}
		events[i] = evt
	}

	// 1. Criterio de Éxito Obligatorio:
	// En un lote de 100 eventos, corromper intencionalmente la nota del evento número 42
	// y verificar que RecordVerificationSummary reporte exactamente CorruptedEvents: 1 con EventIndex: 42.
	const targetCorruptIndex = 42

	switch e := events[targetCorruptIndex].(type) {
	case *domain.GradeRegistrationEvent:
		// Alterar la nota sin recalcular el hash
		if e.Payload.Grade > 2.5 {
			e.Payload.Grade = 1.0
		} else {
			e.Payload.Grade = 5.0
		}
	case *domain.GradeModificationEvent:
		// Alterar la nueva nota sin recalcular el hash
		if e.Payload.NewGrade > 2.5 {
			e.Payload.NewGrade = 1.0
		} else {
			e.Payload.NewGrade = 5.0
		}
	default:
		t.Fatalf("unsupported event type at target index %d: %T", targetCorruptIndex, events[targetCorruptIndex])
	}

	consolidatedLog := storage.NewConsolidatedAcademicLog(events)

	// Ejecutar la auditoría forense registro por registro
	summary := VerifyAllRecords(consolidatedLog)

	if summary.TotalEvents != 100 {
		t.Errorf("expected TotalEvents 100, got %d", summary.TotalEvents)
	}

	if summary.ValidEvents != 99 {
		t.Errorf("expected ValidEvents 99, got %d", summary.ValidEvents)
	}

	if summary.CorruptedEvents != 1 {
		t.Fatalf("expected CorruptedEvents exactly 1, got %d", summary.CorruptedEvents)
	}

	if len(summary.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(summary.Findings))
	}

	finding := summary.Findings[0]
	if finding.EventIndex != targetCorruptIndex {
		t.Errorf("expected finding EventIndex %d, got %d", targetCorruptIndex, finding.EventIndex)
	}

	if finding.IsValid {
		t.Errorf("expected finding IsValid to be false")
	}

	if finding.CalculatedHash == finding.ExpectedHash {
		t.Errorf("calculated hash cannot match expected hash on tampered record")
	}

	if finding.EventID != events[targetCorruptIndex].GetEventID() {
		t.Errorf("expected EventID %s, got %s", events[targetCorruptIndex].GetEventID(), finding.EventID)
	}
}

func TestVerifyAllRecords_AllValid(t *testing.T) {
	r := rand.New(rand.NewPCG(99, 2048))
	orch := generator.NewEventOrchestrator(nil, r)

	rawSequence, err := orch.GenerateSequence(25)
	if err != nil {
		t.Fatalf("failed to generate events: %v", err)
	}

	events := make([]domain.GenericEvent, len(rawSequence))
	for i, raw := range rawSequence {
		evt := raw.(domain.GenericEvent)
		_ = crypto.SignEventPayload(evt)
		events[i] = evt
	}

	log := storage.NewConsolidatedAcademicLog(events)
	summary := VerifyAllRecords(log)

	if summary.TotalEvents != 25 || summary.ValidEvents != 25 || summary.CorruptedEvents != 0 {
		t.Errorf("unexpected summary for valid log: %+v", summary)
	}
	if len(summary.Findings) != 0 {
		t.Errorf("expected 0 findings for valid log, got %d", len(summary.Findings))
	}
}

func TestVerifyAllRecords_EdgeCases(t *testing.T) {
	// 1. Log nulo o vacío: totals en 0 y sin pánico
	emptySummary1 := VerifyAllRecords(nil)
	if emptySummary1.TotalEvents != 0 || emptySummary1.ValidEvents != 0 || emptySummary1.CorruptedEvents != 0 {
		t.Errorf("nil log should return zero totals, got: %+v", emptySummary1)
	}

	emptySummary2 := VerifyAllRecords(&storage.ConsolidatedAcademicLog{Events: nil})
	if emptySummary2.TotalEvents != 0 {
		t.Errorf("empty events should return zero totals, got: %+v", emptySummary2)
	}

	// 2. Registro con PayloadHash vacío
	unsignedPayload := domain.GradeRegistrationPayload{
		StudentUID:   "STU-100",
		SubjectUID:   "SUB-100",
		EvaluatorUID: "DOC-100",
		Grade:        4.5,
		Evaluation:   "Taller 1",
		Timestamp:    time.Now().UTC().Add(-1 * time.Hour),
	}
	unsignedEvt, err := domain.NewGradeRegistrationEvent("EVT-UNSIGNED-01", unsignedPayload)
	if err != nil {
		t.Fatalf("failed to create unsigned event: %v", err)
	}

	logWithUnsigned := storage.NewConsolidatedAcademicLog([]domain.GenericEvent{unsignedEvt})
	summaryUnsigned := VerifyAllRecords(logWithUnsigned)

	if summaryUnsigned.CorruptedEvents != 1 {
		t.Errorf("expected unsigned event to be flagged as corrupted, got: %+v", summaryUnsigned)
	}
	if len(summaryUnsigned.Findings) != 1 || summaryUnsigned.Findings[0].ExpectedHash != "ausencia de digest" {
		t.Errorf("expected 'ausencia de digest' finding, got: %+v", summaryUnsigned.Findings)
	}
}

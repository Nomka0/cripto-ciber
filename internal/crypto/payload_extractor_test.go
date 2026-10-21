package crypto

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"taller2-criptografia/internal/domain"
)

func TestExtractPayloadBytes(t *testing.T) {
	fixedTime := time.Date(2026, time.March, 15, 10, 30, 0, 0, time.UTC)

	t.Run("GradeRegistrationEvent independence of payload_hash", func(t *testing.T) {
		payload := domain.GradeRegistrationPayload{
			StudentUID:   "STD-2026-001",
			SubjectUID:   "SUBJ-MAT-101",
			EvaluatorUID: "PROF-999",
			Grade:        4.5,
			Evaluation:   "Parcial 1",
			Timestamp:    fixedTime,
		}

		eventWithoutHash := domain.GradeRegistrationEvent{
			EventID:     "EVT-REG-001",
			EventType:   domain.EventTypeRegistration,
			Payload:     payload,
			PayloadHash: "",
		}

		eventWithHashA := domain.GradeRegistrationEvent{
			EventID:     "EVT-REG-001",
			EventType:   domain.EventTypeRegistration,
			Payload:     payload,
			PayloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		}

		eventWithHashB := domain.GradeRegistrationEvent{
			EventID:     "EVT-REG-999",
			EventType:   domain.EventTypeRegistration,
			Payload:     payload,
			PayloadHash: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
		}

		bytesEmpty, err := ExtractPayloadBytes(eventWithoutHash)
		if err != nil {
			t.Fatalf("unexpected error for eventWithoutHash: %v", err)
		}

		bytesHashA, err := ExtractPayloadBytes(eventWithHashA)
		if err != nil {
			t.Fatalf("unexpected error for eventWithHashA: %v", err)
		}

		bytesHashB, err := ExtractPayloadBytes(&eventWithHashB)
		if err != nil {
			t.Fatalf("unexpected error for pointer to eventWithHashB: %v", err)
		}

		bytesDirectPayload, err := ExtractPayloadBytes(payload)
		if err != nil {
			t.Fatalf("unexpected error for direct payload: %v", err)
		}

		if !bytes.Equal(bytesEmpty, bytesHashA) {
			t.Errorf("bytes differ between empty and populated payload_hash:\nempty: %s\nhashA: %s", bytesEmpty, bytesHashA)
		}

		if !bytes.Equal(bytesEmpty, bytesHashB) {
			t.Errorf("bytes differ between empty and different event_id/hash:\nempty: %s\nhashB: %s", bytesEmpty, bytesHashB)
		}

		if !bytes.Equal(bytesEmpty, bytesDirectPayload) {
			t.Errorf("bytes differ between event container and direct payload:\nevent:   %s\npayload: %s", bytesEmpty, bytesDirectPayload)
		}

		// Ensure container metadata is absent
		if bytes.Contains(bytesEmpty, []byte("payload_hash")) {
			t.Errorf("extracted payload contains circular metadata payload_hash: %s", bytesEmpty)
		}
		if bytes.Contains(bytesEmpty, []byte("event_id")) {
			t.Errorf("extracted payload contains container event_id: %s", bytesEmpty)
		}
	})

	t.Run("GradeModificationEvent independence of payload_hash", func(t *testing.T) {
		payload := domain.GradeModificationPayload{
			StudentUID:    "STD-2026-002",
			SubjectUID:    "SUBJ-FIS-201",
			ModifierUID:   "PROF-888",
			PreviousGrade: 3.0,
			NewGrade:      4.2,
			Reason:        "Revision detallada del informe de laboratorio 2",
			Evaluation:    "Laboratorio 2",
			Timestamp:     fixedTime,
		}

		eventWithoutHash := domain.GradeModificationEvent{
			EventID:     "EVT-MOD-001",
			EventType:   domain.EventTypeModification,
			Payload:     payload,
			PayloadHash: "",
		}

		eventWithHash := domain.GradeModificationEvent{
			EventID:     "EVT-MOD-001",
			EventType:   domain.EventTypeModification,
			Payload:     payload,
			PayloadHash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		}

		bytesEmpty, err := ExtractPayloadBytes(eventWithoutHash)
		if err != nil {
			t.Fatalf("unexpected error for eventWithoutHash: %v", err)
		}

		bytesWithHash, err := ExtractPayloadBytes(eventWithHash)
		if err != nil {
			t.Fatalf("unexpected error for eventWithHash: %v", err)
		}

		bytesDirect, err := ExtractPayloadBytes(&payload)
		if err != nil {
			t.Fatalf("unexpected error for pointer to payload: %v", err)
		}

		if !bytes.Equal(bytesEmpty, bytesWithHash) {
			t.Errorf("bytes differ for modification event with hash:\nempty: %s\nhash:  %s", bytesEmpty, bytesWithHash)
		}

		if !bytes.Equal(bytesEmpty, bytesDirect) {
			t.Errorf("bytes differ between modification event and direct payload:\nevent:   %s\npayload: %s", bytesEmpty, bytesDirect)
		}

		if bytes.Contains(bytesEmpty, []byte("payload_hash")) {
			t.Errorf("extracted payload contains circular metadata payload_hash: %s", bytesEmpty)
		}
		if bytes.Contains(bytesEmpty, []byte("event_id")) {
			t.Errorf("extracted payload contains container event_id: %s", bytesEmpty)
		}
	})
}

func TestExtractPayloadBytes_Deterministic(t *testing.T) {
	fixedTime := time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC)
	payload := domain.GradeRegistrationPayload{
		StudentUID:   "STD-123",
		SubjectUID:   "SUBJ-456",
		EvaluatorUID: "DOC-789",
		Grade:        5.0,
		Evaluation:   "Examen Final",
		Timestamp:    fixedTime,
	}

	firstRun, err := ExtractPayloadBytes(payload)
	if err != nil {
		t.Fatalf("first run failed: %v", err)
	}

	for i := 0; i < 50; i++ {
		subsequentRun, err := ExtractPayloadBytes(payload)
		if err != nil {
			t.Fatalf("iteration %d failed: %v", i, err)
		}
		if !bytes.Equal(firstRun, subsequentRun) {
			t.Fatalf("non-deterministic output at iteration %d:\nfirst: %s\ngot:   %s", i, firstRun, subsequentRun)
		}
	}
}

func TestExtractPayload_ValidationAndErrors(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		_, err := ExtractPayloadBytes(nil)
		if !errors.Is(err, ErrNilPayload) {
			t.Errorf("expected ErrNilPayload, got %v", err)
		}
	})

	t.Run("nil pointer to registration event", func(t *testing.T) {
		var nilRegEvent *domain.GradeRegistrationEvent
		_, err := ExtractPayloadBytes(nilRegEvent)
		if !errors.Is(err, ErrNilPayload) {
			t.Errorf("expected ErrNilPayload, got %v", err)
		}
	})

	t.Run("nil pointer to modification event", func(t *testing.T) {
		var nilModEvent *domain.GradeModificationEvent
		_, err := ExtractPayloadBytes(nilModEvent)
		if !errors.Is(err, ErrNilPayload) {
			t.Errorf("expected ErrNilPayload, got %v", err)
		}
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := ExtractPayloadBytes("not-a-valid-payload")
		if !errors.Is(err, ErrUnsupportedPayloadType) {
			t.Errorf("expected ErrUnsupportedPayloadType, got %v", err)
		}

		type fakeContainer struct {
			Data string `json:"data"`
		}
		_, err = ExtractPayloadBytes(fakeContainer{Data: "test"})
		if !errors.Is(err, ErrUnsupportedPayloadType) {
			t.Errorf("expected ErrUnsupportedPayloadType, got %v", err)
		}
	})
}

func TestTypedExtractors(t *testing.T) {
	fixedTime := time.Date(2026, time.May, 10, 8, 0, 0, 0, time.UTC)

	regPayload := domain.GradeRegistrationPayload{
		StudentUID:   "STD-R1",
		SubjectUID:   "SUBJ-R1",
		EvaluatorUID: "PROF-R1",
		Grade:        3.8,
		Evaluation:   "Quiz 1",
		Timestamp:    fixedTime,
	}
	regEvent := domain.GradeRegistrationEvent{
		EventID:     "EVT-R1",
		EventType:   domain.EventTypeRegistration,
		Payload:     regPayload,
		PayloadHash: "dummy-hash",
	}

	modPayload := domain.GradeModificationPayload{
		StudentUID:    "STD-M1",
		SubjectUID:    "SUBJ-M1",
		ModifierUID:   "PROF-M1",
		PreviousGrade: 3.5,
		NewGrade:      4.0,
		Reason:        "Ajuste por reclamo sustentado en clase",
		Evaluation:    "Quiz 1",
		Timestamp:     fixedTime,
	}
	modEvent := domain.GradeModificationEvent{
		EventID:     "EVT-M1",
		EventType:   domain.EventTypeModification,
		Payload:     modPayload,
		PayloadHash: "dummy-hash-2",
	}

	t.Run("ExtractRegistrationPayload and ExtractRegistrationPayloadBytes", func(t *testing.T) {
		p, err := ExtractRegistrationPayload(&regEvent)
		if err != nil || p.StudentUID != "STD-R1" {
			t.Fatalf("ExtractRegistrationPayload failed: %v", err)
		}

		b, err := ExtractRegistrationPayloadBytes(regEvent)
		if err != nil {
			t.Fatalf("ExtractRegistrationPayloadBytes failed: %v", err)
		}

		bGeneric, err := ExtractPayloadBytes(regEvent)
		if err != nil || !bytes.Equal(b, bGeneric) {
			t.Errorf("mismatch between typed and generic extraction bytes")
		}

		// Wrong type should fail
		_, err = ExtractRegistrationPayload(modEvent)
		if !errors.Is(err, ErrUnsupportedPayloadType) {
			t.Errorf("expected ErrUnsupportedPayloadType, got %v", err)
		}
	})

	t.Run("ExtractModificationPayload and ExtractModificationPayloadBytes", func(t *testing.T) {
		p, err := ExtractModificationPayload(&modEvent)
		if err != nil || p.StudentUID != "STD-M1" {
			t.Fatalf("ExtractModificationPayload failed: %v", err)
		}

		b, err := ExtractModificationPayloadBytes(modEvent)
		if err != nil {
			t.Fatalf("ExtractModificationPayloadBytes failed: %v", err)
		}

		bGeneric, err := ExtractPayloadBytes(modEvent)
		if err != nil || !bytes.Equal(b, bGeneric) {
			t.Errorf("mismatch between typed and generic extraction bytes")
		}

		// Wrong type should fail
		_, err = ExtractModificationPayload(regEvent)
		if !errors.Is(err, ErrUnsupportedPayloadType) {
			t.Errorf("expected ErrUnsupportedPayloadType, got %v", err)
		}
	})
}

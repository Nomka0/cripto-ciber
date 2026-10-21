package crypto

import (
	"errors"
	"testing"
	"time"

	"taller2-criptografia/internal/domain"
)

func TestSignAndVerifyEvent(t *testing.T) {
	fixedTime := time.Date(2026, time.June, 10, 9, 0, 0, 0, time.UTC)

	t.Run("GradeRegistrationEvent signing, verification and tampering detection", func(t *testing.T) {
		payload := domain.GradeRegistrationPayload{
			StudentUID:   "STD-SIGN-01",
			SubjectUID:   "SUBJ-SIGN-01",
			EvaluatorUID: "PROF-SIGN-01",
			Grade:        4.2,
			Evaluation:   "Examen Parcial",
			Timestamp:    fixedTime,
		}

		event, err := domain.NewGradeRegistrationEvent("EVT-REG-100", payload)
		if err != nil {
			t.Fatalf("unexpected error creating registration event: %v", err)
		}

		// 1. Prior to signing, verification must return false because PayloadHash is empty
		valid, err := VerifyEventPayloadHash(event)
		if err != nil {
			t.Fatalf("unexpected error verifying unsigned event: %v", err)
		}
		if valid {
			t.Fatal("expected unsigned event verification to be false")
		}

		// 2. Sign the event
		if err := SignEventPayload(event); err != nil {
			t.Fatalf("failed to sign event: %v", err)
		}

		if len(event.PayloadHash) != 64 {
			t.Fatalf("expected 64 characters hex hash, got length %d (%s)", len(event.PayloadHash), event.PayloadHash)
		}

		// 3. Verify signed event
		valid, err = VerifyEventPayloadHash(event)
		if err != nil {
			t.Fatalf("unexpected error during verification: %v", err)
		}
		if !valid {
			t.Fatal("expected signed event verification to be true")
		}

		// 4. Deliberately alter the grade in the payload
		originalGrade := event.Payload.Grade
		event.Payload.Grade = 1.0

		valid, err = VerifyEventPayloadHash(event)
		if err != nil {
			t.Fatalf("unexpected error verifying tampered event: %v", err)
		}
		if valid {
			t.Fatal("expected tampered event verification to be false when grade changed")
		}

		// 5. Restore grade and tamper with the hash directly
		event.Payload.Grade = originalGrade
		event.PayloadHash = "0000000000000000000000000000000000000000000000000000000000000000"

		valid, err = VerifyEventPayloadHash(event)
		if err != nil {
			t.Fatalf("unexpected error verifying tampered hash: %v", err)
		}
		if valid {
			t.Fatal("expected verification to be false when hash is tampered")
		}
	})

	t.Run("GradeModificationEvent signing, verification and tampering detection", func(t *testing.T) {
		payload := domain.GradeModificationPayload{
			StudentUID:    "STD-SIGN-02",
			SubjectUID:    "SUBJ-SIGN-02",
			ModifierUID:   "PROF-SIGN-02",
			PreviousGrade: 3.0,
			NewGrade:      4.5,
			Reason:        "Revisión de sustanciación de proyecto final",
			Evaluation:    "Proyecto Final",
			Timestamp:     fixedTime,
		}

		event, err := domain.NewGradeModificationEvent("EVT-MOD-200", payload)
		if err != nil {
			t.Fatalf("unexpected error creating modification event: %v", err)
		}

		// Sign with EventEnricher interface
		enricher := NewEventEnricher()
		if err := enricher.EnrichWithHash(event); err != nil {
			t.Fatalf("enricher failed to sign event: %v", err)
		}

		valid, err := VerifyEventPayloadHash(event)
		if err != nil {
			t.Fatalf("unexpected error verifying modification event: %v", err)
		}
		if !valid {
			t.Fatal("expected signed modification event to verify successfully")
		}

		// Alter reason
		event.Payload.Reason = "Razón completamente inventada o adulterada"
		valid, err = VerifyEventPayloadHash(event)
		if err != nil {
			t.Fatalf("unexpected error verifying altered reason: %v", err)
		}
		if valid {
			t.Fatal("expected verification to fail when reason is altered")
		}
	})

	t.Run("Controlled overwrite of pre-existing hash", func(t *testing.T) {
		payload := domain.GradeRegistrationPayload{
			StudentUID:   "STD-OVERWRITE",
			SubjectUID:   "SUBJ-OVERWRITE",
			EvaluatorUID: "PROF-OVERWRITE",
			Grade:        3.5,
			Evaluation:   "Quiz",
			Timestamp:    fixedTime,
		}

		event, _ := domain.NewGradeRegistrationEvent("EVT-REG-300", payload)
		event.PayloadHash = "stale-pre-existing-hash"

		if err := SignEventPayload(event); err != nil {
			t.Fatalf("expected successful overwrite: %v", err)
		}

		if event.PayloadHash == "stale-pre-existing-hash" {
			t.Fatal("expected payload hash to be overwritten with fresh digest")
		}

		valid, err := VerifyEventPayloadHash(event)
		if err != nil || !valid {
			t.Fatalf("expected valid verification after overwrite, valid=%v, err=%v", valid, err)
		}
	})

	t.Run("Nil event error handling", func(t *testing.T) {
		err := SignEventPayload(nil)
		if !errors.Is(err, ErrNilEvent) {
			t.Fatalf("expected ErrNilEvent for nil SignEventPayload, got %v", err)
		}

		valid, err := VerifyEventPayloadHash(nil)
		if !errors.Is(err, ErrNilEvent) || valid {
			t.Fatalf("expected ErrNilEvent for nil VerifyEventPayloadHash, got valid=%v, err=%v", valid, err)
		}

		var nilReg *domain.GradeRegistrationEvent
		err = SignEventPayload(nilReg)
		if !errors.Is(err, ErrNilEvent) {
			t.Fatalf("expected ErrNilEvent for typed nil event, got %v", err)
		}
	})
}

package domain

import (
	"errors"
	"testing"
	"time"
)

func TestGradeModification(t *testing.T) {
	basePayload := func() GradeModificationPayload {
		return GradeModificationPayload{
			StudentUID:    "USR-STUDENT-001",
			SubjectUID:    "SUB-CRIPTO-101",
			ModifierUID:   "USR-DOCENTE-001",
			PreviousGrade: 2.5,
			NewGrade:      4.0,
			Reason:        "Corrección formal tras revisión de reclamo presencial",
			Evaluation:    "Parcial 1",
			Timestamp:     time.Now().UTC(),
		}
	}

	t.Run("Modificación de 2.5 a 4.0 con razón válida aceptada", func(t *testing.T) {
		p := basePayload()
		evt, err := NewGradeModificationEvent("EVT-MOD-001", p)
		if err != nil {
			t.Fatalf("expected valid modification, got error: %v", err)
		}
		if evt.EventType != EventTypeModification {
			t.Fatalf("expected EventTypeModification, got %s", evt.EventType)
		}
		if evt.Payload.PreviousGrade != 2.5 || evt.Payload.NewGrade != 4.0 {
			t.Fatalf("unexpected grades: %f, %f", evt.Payload.PreviousGrade, evt.Payload.NewGrade)
		}
	})

	t.Run("Modificación de 3.0 a 3.0 rechazada con ErrIdenticalGrades", func(t *testing.T) {
		p := basePayload()
		p.PreviousGrade = 3.0
		p.NewGrade = 3.0
		_, err := NewGradeModificationEvent("EVT-MOD-002", p)
		if !errors.Is(err, ErrIdenticalGrades) {
			t.Fatalf("expected ErrIdenticalGrades, got: %v", err)
		}

		// Caso con redondeo que da notas idénticas
		p.PreviousGrade = 3.001
		p.NewGrade = 3.004
		_, err = NewGradeModificationEvent("EVT-MOD-002-ROUND", p)
		if !errors.Is(err, ErrIdenticalGrades) {
			t.Fatalf("expected ErrIdenticalGrades after rounding, got: %v", err)
		}
	})

	t.Run("Modificación con nota nueva 5.5 rechazada por fuera de rango", func(t *testing.T) {
		p := basePayload()
		p.NewGrade = 5.5
		_, err := NewGradeModificationEvent("EVT-MOD-003", p)
		if !errors.Is(err, ErrInvalidNewGrade) {
			t.Fatalf("expected ErrInvalidNewGrade, got: %v", err)
		}

		p = basePayload()
		p.PreviousGrade = -0.5
		_, err = NewGradeModificationEvent("EVT-MOD-003-PREV", p)
		if !errors.Is(err, ErrInvalidPreviousGrade) {
			t.Fatalf("expected ErrInvalidPreviousGrade, got: %v", err)
		}
	})

	t.Run("Razón de modificación menor a 10 caracteres rechazada", func(t *testing.T) {
		p := basePayload()
		p.Reason = "error"
		_, err := NewGradeModificationEvent("EVT-MOD-004", p)
		if !errors.Is(err, ErrReasonTooShort) {
			t.Fatalf("expected ErrReasonTooShort, got: %v", err)
		}
	})

	t.Run("UIDs vacíos o EventID vacío rechazados", func(t *testing.T) {
		p := basePayload()
		if _, err := NewGradeModificationEvent("", p); !errors.Is(err, ErrEmptyEventID) {
			t.Fatalf("expected ErrEmptyEventID, got: %v", err)
		}

		p.ModifierUID = "  "
		if _, err := NewGradeModificationEvent("EVT-MOD-005", p); !errors.Is(err, ErrEmptyModifierUID) {
			t.Fatalf("expected ErrEmptyModifierUID, got: %v", err)
		}
	})
}

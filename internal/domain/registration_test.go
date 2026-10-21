package domain

import (
	"errors"
	"testing"
	"time"
)

func TestGradeRegistration(t *testing.T) {
	basePayload := func() GradeRegistrationPayload {
		return GradeRegistrationPayload{
			StudentUID:   "USR-STUDENT-001",
			SubjectUID:   "SUB-CRIPTO-101",
			EvaluatorUID: "USR-DOCENTE-001",
			Grade:        3.5,
			Evaluation:   "Parcial 1",
			Timestamp:    time.Now().UTC(),
		}
	}

	t.Run("Nota valida 3.5", func(t *testing.T) {
		p := basePayload()
		p.Grade = 3.5
		evt, err := NewGradeRegistrationEvent("EVT-REG-001", p)
		if err != nil {
			t.Fatalf("expected valid registration, got err: %v", err)
		}
		if evt.Payload.Grade != 3.5 {
			t.Fatalf("expected grade 3.5, got %f", evt.Payload.Grade)
		}
		if evt.EventType != EventTypeRegistration {
			t.Fatalf("expected EventTypeRegistration, got %s", evt.EventType)
		}
	})

	t.Run("Notas limite 0.0 y 5.0 aceptadas", func(t *testing.T) {
		for _, g := range []float64{0.0, 5.0} {
			p := basePayload()
			p.Grade = g
			evt, err := NewGradeRegistrationEvent("EVT-REG-002", p)
			if err != nil {
				t.Fatalf("expected valid grade for %f, got err: %v", g, err)
			}
			if evt.Payload.Grade != g {
				t.Fatalf("expected grade %f, got %f", g, evt.Payload.Grade)
			}
		}
	})

	t.Run("Notas fuera de rango -0.1 y 5.01 rechazadas", func(t *testing.T) {
		for _, g := range []float64{-0.1, 5.01} {
			p := basePayload()
			p.Grade = g
			_, err := NewGradeRegistrationEvent("EVT-REG-003", p)
			if !errors.Is(err, ErrInvalidGradeRange) {
				t.Fatalf("expected ErrInvalidGradeRange for grade %f, got: %v", g, err)
			}
		}
	})

	t.Run("Timestamp nulo o futuro irreal rechazado", func(t *testing.T) {
		p := basePayload()
		p.Timestamp = time.Time{}
		if _, err := NewGradeRegistrationEvent("EVT-REG-004", p); !errors.Is(err, ErrZeroTimestamp) {
			t.Fatalf("expected ErrZeroTimestamp, got: %v", err)
		}

		p.Timestamp = time.Now().Add(10 * time.Minute)
		if _, err := NewGradeRegistrationEvent("EVT-REG-004", p); !errors.Is(err, ErrFutureTimestamp) {
			t.Fatalf("expected ErrFutureTimestamp, got: %v", err)
		}
	})

	t.Run("UIDs vacios o EventID vacio rechazados", func(t *testing.T) {
		p := basePayload()
		if _, err := NewGradeRegistrationEvent("", p); !errors.Is(err, ErrEmptyEventID) {
			t.Fatalf("expected ErrEmptyEventID, got: %v", err)
		}

		tests := []struct {
			name        string
			mutate      func(*GradeRegistrationPayload)
			expectedErr error
		}{
			{"empty student_uid", func(p *GradeRegistrationPayload) { p.StudentUID = "  " }, ErrEmptyStudentUID},
			{"empty subject_uid", func(p *GradeRegistrationPayload) { p.SubjectUID = "  " }, ErrEmptySubjectUID},
			{"empty evaluator_uid", func(p *GradeRegistrationPayload) { p.EvaluatorUID = "  " }, ErrEmptyEvaluatorUID},
			{"empty evaluation", func(p *GradeRegistrationPayload) { p.Evaluation = "  " }, ErrEmptyEvaluationName},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				payload := basePayload()
				tc.mutate(&payload)
				_, err := NewGradeRegistrationEvent("EVT-REG-005", payload)
				if !errors.Is(err, tc.expectedErr) {
					t.Fatalf("expected %v, got %v", tc.expectedErr, err)
				}
			})
		}
	})
}

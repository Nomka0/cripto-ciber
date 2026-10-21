package generator

import (
	"math/rand/v2"
	"testing"
	"time"

	"taller2-criptografia/internal/domain"
)

func TestEventAlternation(t *testing.T) {
	t.Run("N=1 produce obligatoriamente REGISTRO_NOTA", func(t *testing.T) {
		orch := NewEventOrchestrator(nil, nil)
		events, err := orch.GenerateSequence(1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(events))
		}
		regEvt, ok := events[0].(*domain.GradeRegistrationEvent)
		if !ok {
			t.Fatalf("expected *domain.GradeRegistrationEvent, got %T", events[0])
		}
		if regEvt.EventType != domain.EventTypeRegistration {
			t.Fatalf("expected EventTypeRegistration, got %s", regEvt.EventType)
		}
	})

	t.Run("N=1000 alternancia coherente y reglas temporales", func(t *testing.T) {
		r := rand.New(rand.NewPCG(1234, 5678))
		gradeGen, _ := NewUniformGradeGeneratorWithRand(0.0, 5.0, r)
		orch := NewEventOrchestrator(gradeGen, r)

		const n = 1000
		events, err := orch.GenerateSequence(n)
		if err != nil {
			t.Fatalf("error generating sequence: %v", err)
		}
		if len(events) != n {
			t.Fatalf("expected %d events, got %d", n, len(events))
		}

		type key struct {
			student string
			subject string
			eval    string
		}

		type currentRecord struct {
			grade     float64
			timestamp time.Time
		}

		latestState := make(map[key]currentRecord)
		regCount := 0
		modCount := 0

		for i, event := range events {
			switch e := event.(type) {
			case *domain.GradeRegistrationEvent:
				regCount++
				k := key{
					student: e.Payload.StudentUID,
					subject: e.Payload.SubjectUID,
					eval:    e.Payload.Evaluation,
				}
				latestState[k] = currentRecord{
					grade:     e.Payload.Grade,
					timestamp: e.Payload.Timestamp,
				}

			case *domain.GradeModificationEvent:
				modCount++
				k := key{
					student: e.Payload.StudentUID,
					subject: e.Payload.SubjectUID,
					eval:    e.Payload.Evaluation,
				}

				rec, exists := latestState[k]
				if !exists {
					t.Fatalf("event #%d: modification without previous registration for %+v", i, k)
				}

				// PreviousGrade == registro previo
				if e.Payload.PreviousGrade != rec.grade {
					t.Fatalf("event #%d: PreviousGrade %f != expected %f", i, e.Payload.PreviousGrade, rec.grade)
				}

				// NewGrade != PreviousGrade
				if e.Payload.NewGrade == e.Payload.PreviousGrade {
					t.Fatalf("event #%d: NewGrade equals PreviousGrade %f", i, e.Payload.NewGrade)
				}

				// timestamp posterior (>= o > registro previo)
				if !e.Payload.Timestamp.After(rec.timestamp) && !e.Payload.Timestamp.Equal(rec.timestamp) {
					t.Fatalf("event #%d: modification timestamp %v is before previous %v",
						i, e.Payload.Timestamp, rec.timestamp)
				}

				// Actualizar estado para futuras modificaciones
				latestState[k] = currentRecord{
					grade:     e.Payload.NewGrade,
					timestamp: e.Payload.Timestamp,
				}

			default:
				t.Fatalf("event #%d: unknown event type %T", i, event)
			}
		}

		if regCount == 0 || modCount == 0 {
			t.Fatalf("expected both registrations and modifications, got reg=%d, mod=%d", regCount, modCount)
		}

		modRatio := float64(modCount) / float64(n)
		if modRatio < 0.20 || modRatio > 0.45 {
			t.Fatalf("modification ratio %f outside expected range [0.20, 0.45]", modRatio)
		}
	})
}

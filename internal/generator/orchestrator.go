package generator

import (
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"taller2-criptografia/internal/domain"
)

type EventOrchestrator struct {
	gradeGen     GradeGenerator
	r            *rand.Rand
	regProb      float64
	studentPool  []string
	subjectPool  []string
	teacherPool  []string
	evalPool     []string
	reasonsPool  []string
	baseTime     time.Time
}

func NewEventOrchestrator(gradeGen GradeGenerator, r *rand.Rand) *EventOrchestrator {
	if gradeGen == nil {
		gradeGen, _ = NewUniformGradeGenerator(0.0, 5.0)
	}
	return &EventOrchestrator{
		gradeGen: gradeGen,
		r:        r,
		regProb:  0.70, // 70% registro, 30% modificacion
		studentPool: []string{
			"USR-STU-001", "USR-STU-002", "USR-STU-003", "USR-STU-004", "USR-STU-005",
			"USR-STU-006", "USR-STU-007", "USR-STU-008", "USR-STU-009", "USR-STU-010",
		},
		subjectPool: []string{"SUB-CRIPTO-101", "SUB-SEG-202", "SUB-REDES-303"},
		teacherPool: []string{"USR-DOC-001", "USR-DOC-002", "USR-DOC-003"},
		evalPool:    []string{"Taller 1", "Taller 2", "Parcial 1", "Examen Final"},
		reasonsPool: []string{
			"Revisión de reclamo presencial y ajuste en punto 3",
			"Error de digitación en la planilla inicial reportado a tiempo",
			"Calificación de entrega extemporánea autorizada por coordinación",
			"Actualización de nota por sustentación oral satisfactoria",
		},
		baseTime: time.Now().UTC().Add(-24 * time.Hour),
	}
}

func (o *EventOrchestrator) randFloat() float64 {
	if o.r != nil {
		return o.r.Float64()
	}
	return rand.Float64()
}

func (o *EventOrchestrator) randIntN(n int) int {
	if o.r != nil {
		return o.r.IntN(n)
	}
	return rand.IntN(n)
}

func (o *EventOrchestrator) GenerateSequence(n int) ([]any, error) {
	if n <= 0 {
		return nil, nil
	}

	events := make([]any, 0, n)
	// pool en memoria para servir de base a modificaciones
	// guardamos el estado mas reciente de cada calificacion
	registeredGrades := make([]domain.GradeRegistrationPayload, 0)

	currTime := o.baseTime

	for i := 1; i <= n; i++ {
		currTime = currTime.Add(time.Duration(1+o.randIntN(10)) * time.Minute)

		shouldRegister := len(registeredGrades) == 0 || o.randFloat() < o.regProb

		if shouldRegister {
			student := o.studentPool[o.randIntN(len(o.studentPool))]
			subject := o.subjectPool[o.randIntN(len(o.subjectPool))]
			evaluator := o.teacherPool[o.randIntN(len(o.teacherPool))]
			eval := o.evalPool[o.randIntN(len(o.evalPool))]
			grade := o.gradeGen.GenerateGrade()

			payload := domain.GradeRegistrationPayload{
				StudentUID:   student,
				SubjectUID:   subject,
				EvaluatorUID: evaluator,
				Grade:        grade,
				Evaluation:   eval,
				Timestamp:    currTime,
			}

			evt, err := domain.NewGradeRegistrationEvent(fmt.Sprintf("EVT-REG-%05d", i), payload)
			if err != nil {
				return nil, fmt.Errorf("error generating registration event: %w", err)
			}

			registeredGrades = append(registeredGrades, payload)
			events = append(events, evt)
		} else {
			// Seleccionar registro previo
			idx := o.randIntN(len(registeredGrades))
			prev := registeredGrades[idx]

			// Generar nueva nota distinta
			var newGrade float64
			for {
				newGrade = o.gradeGen.GenerateGrade()
				if math.Abs(newGrade-prev.Grade) >= 0.01 {
					break
				}
			}

			reason := o.reasonsPool[o.randIntN(len(o.reasonsPool))]
			modifier := o.teacherPool[o.randIntN(len(o.teacherPool))]

			payload := domain.GradeModificationPayload{
				StudentUID:    prev.StudentUID,
				SubjectUID:    prev.SubjectUID,
				ModifierUID:   modifier,
				PreviousGrade: prev.Grade,
				NewGrade:      newGrade,
				Reason:        reason,
				Evaluation:    prev.Evaluation,
				Timestamp:     currTime,
			}

			evt, err := domain.NewGradeModificationEvent(fmt.Sprintf("EVT-MOD-%05d", i), payload)
			if err != nil {
				return nil, fmt.Errorf("error generating modification event: %w", err)
			}

			// Actualizar nota en el pool para reflejar el estado actual
			registeredGrades[idx].Grade = newGrade
			registeredGrades[idx].Timestamp = currTime

			events = append(events, evt)
		}
	}

	return events, nil
}

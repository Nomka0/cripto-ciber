package domain

import (
	"errors"
	"math"
	"strings"
	"time"
)

var (
	ErrInvalidGradeRange   = errors.New("grade out of range [0.0, 5.0]")
	ErrEmptyStudentUID     = errors.New("student_uid cannot be empty")
	ErrEmptyEvaluatorUID   = errors.New("evaluator_uid cannot be empty")
	ErrEmptyEvaluationName = errors.New("evaluation cannot be empty")
	ErrFutureTimestamp     = errors.New("timestamp cannot be in the future beyond 5 minutes")
)

type GradeRegistrationPayload struct {
	StudentUID   string    `json:"student_uid"`
	SubjectUID   string    `json:"subject_uid"`
	EvaluatorUID string    `json:"evaluator_uid"`
	Grade        float64   `json:"grade"`
	Evaluation   string    `json:"evaluation"` // Ej: "Parcial 1", "Taller 2"
	Timestamp    time.Time `json:"timestamp"`
}

func (p *GradeRegistrationPayload) Validate() error {
	p.Grade = math.Round(p.Grade*100) / 100
	if p.Grade < 0.0 || p.Grade > 5.0 {
		return ErrInvalidGradeRange
	}
	if strings.TrimSpace(p.StudentUID) == "" {
		return ErrEmptyStudentUID
	}
	if strings.TrimSpace(p.SubjectUID) == "" {
		return ErrEmptySubjectUID
	}
	if strings.TrimSpace(p.EvaluatorUID) == "" {
		return ErrEmptyEvaluatorUID
	}
	if strings.TrimSpace(p.Evaluation) == "" {
		return ErrEmptyEvaluationName
	}
	if p.Timestamp.IsZero() {
		return ErrZeroTimestamp
	}
	if p.Timestamp.After(time.Now().Add(5 * time.Minute)) {
		return ErrFutureTimestamp
	}
	return nil
}

type GradeRegistrationEvent struct {
	EventID     string                   `json:"event_id"`
	EventType   EventType                `json:"event_type"` // Debe ser REGISTRO_NOTA
	Payload     GradeRegistrationPayload `json:"payload"`
	PayloadHash string                   `json:"payload_hash,omitempty"`
}

func (e GradeRegistrationEvent) GetEventID() string      { return e.EventID }
func (e GradeRegistrationEvent) GetEventType() EventType { return e.EventType }
func (e GradeRegistrationEvent) GetPayloadHash() string  { return e.PayloadHash }

func NewGradeRegistrationEvent(eventID string, payload GradeRegistrationPayload) (*GradeRegistrationEvent, error) {
	if strings.TrimSpace(eventID) == "" {
		return nil, ErrEmptyEventID
	}
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	return &GradeRegistrationEvent{
		EventID:   eventID,
		EventType: EventTypeRegistration,
		Payload:   payload,
	}, nil
}

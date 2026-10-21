package domain

import (
	"errors"
	"math"
	"strings"
	"time"
)

var (
	ErrIdenticalGrades      = errors.New("previous_grade and new_grade cannot be identical")
	ErrEmptyModifierUID     = errors.New("modifier_uid cannot be empty")
	ErrReasonTooShort       = errors.New("reason must be at least 10 characters long")
	ErrInvalidPreviousGrade = errors.New("previous_grade out of range [0.0, 5.0]")
	ErrInvalidNewGrade      = errors.New("new_grade out of range [0.0, 5.0]")
)

type GradeModificationPayload struct {
	StudentUID    string    `json:"student_uid"`
	SubjectUID    string    `json:"subject_uid"`
	ModifierUID   string    `json:"modifier_uid"`
	PreviousGrade float64   `json:"previous_grade"`
	NewGrade      float64   `json:"new_grade"`
	Reason        string    `json:"reason"`
	Evaluation    string    `json:"evaluation"`
	Timestamp     time.Time `json:"timestamp"`
}

func (p *GradeModificationPayload) Validate() error {
	p.PreviousGrade = math.Round(p.PreviousGrade*100) / 100
	p.NewGrade = math.Round(p.NewGrade*100) / 100

	if p.PreviousGrade < 0.0 || p.PreviousGrade > 5.0 {
		return ErrInvalidPreviousGrade
	}
	if p.NewGrade < 0.0 || p.NewGrade > 5.0 {
		return ErrInvalidNewGrade
	}
	if math.Abs(p.PreviousGrade-p.NewGrade) < 0.001 {
		return ErrIdenticalGrades
	}
	if strings.TrimSpace(p.StudentUID) == "" {
		return ErrEmptyStudentUID
	}
	if strings.TrimSpace(p.SubjectUID) == "" {
		return ErrEmptySubjectUID
	}
	if strings.TrimSpace(p.ModifierUID) == "" {
		return ErrEmptyModifierUID
	}
	if strings.TrimSpace(p.Evaluation) == "" {
		return ErrEmptyEvaluationName
	}
	if len(strings.TrimSpace(p.Reason)) < 10 {
		return ErrReasonTooShort
	}
	if p.Timestamp.IsZero() {
		return ErrZeroTimestamp
	}
	if p.Timestamp.After(time.Now().Add(5 * time.Minute)) {
		return ErrFutureTimestamp
	}
	return nil
}

type GradeModificationEvent struct {
	EventID     string                   `json:"event_id"`
	EventType   EventType                `json:"event_type"` // MODIFICACION_NOTA
	Payload     GradeModificationPayload `json:"payload"`
	PayloadHash string                   `json:"payload_hash,omitempty"`
}

func (e GradeModificationEvent) GetEventID() string      { return e.EventID }
func (e GradeModificationEvent) GetEventType() EventType { return e.EventType }
func (e GradeModificationEvent) GetPayloadHash() string  { return e.PayloadHash }

func NewGradeModificationEvent(eventID string, payload GradeModificationPayload) (*GradeModificationEvent, error) {
	if strings.TrimSpace(eventID) == "" {
		return nil, ErrEmptyEventID
	}
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	return &GradeModificationEvent{
		EventID:   eventID,
		EventType: EventTypeModification,
		Payload:   payload,
	}, nil
}

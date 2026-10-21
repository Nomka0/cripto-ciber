package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrEmptyActorUID    = errors.New("actor_uid cannot be empty")
	ErrInvalidActorRole = errors.New("invalid actor role")
	ErrEmptySubjectUID  = errors.New("subject_uid cannot be empty")
	ErrEmptyPeriod      = errors.New("period cannot be empty")
	ErrEmptyCourseGroup = errors.New("course_group cannot be empty")
	ErrEmptyEventID     = errors.New("event_id cannot be empty")
	ErrInvalidEventType = errors.New("invalid event type")
	ErrZeroTimestamp    = errors.New("timestamp cannot be zero")
)

type EventType string

const (
	EventTypeRegistration EventType = "REGISTRO_NOTA"
	EventTypeModification EventType = "MODIFICACION_NOTA"
)

func (e EventType) IsValid() bool {
	switch e {
	case EventTypeRegistration, EventTypeModification:
		return true
	default:
		return false
	}
}

type ActorRole string

const (
	RoleTeacher     ActorRole = "DOCENTE"
	RoleCoordinator ActorRole = "COORDINADOR"
	RoleSystemAdmin ActorRole = "ADMIN_SISTEMA"
)

func (r ActorRole) IsValid() bool {
	switch r {
	case RoleTeacher, RoleCoordinator, RoleSystemAdmin:
		return true
	default:
		return false
	}
}

// BaseActor representa a un usuario dentro del sistema sin PII
type BaseActor struct {
	ActorUID string    `json:"actor_uid"`
	Role     ActorRole `json:"role"`
}

func (a BaseActor) Validate() error {
	if strings.TrimSpace(a.ActorUID) == "" {
		return ErrEmptyActorUID
	}
	if !a.Role.IsValid() {
		return fmt.Errorf("%w: %s", ErrInvalidActorRole, a.Role)
	}
	return nil
}

// AcademicContext identifica el curso y periodo
type AcademicContext struct {
	SubjectUID  string `json:"subject_uid"`
	Period      string `json:"period"`       // Ej: "2026-1"
	CourseGroup string `json:"course_group"` // Ej: "G01"
}

func (c AcademicContext) Validate() error {
	if strings.TrimSpace(c.SubjectUID) == "" {
		return ErrEmptySubjectUID
	}
	if strings.TrimSpace(c.Period) == "" {
		return ErrEmptyPeriod
	}
	if strings.TrimSpace(c.CourseGroup) == "" {
		return ErrEmptyCourseGroup
	}
	return nil
}

// BaseAcademicEvent modela los atributos comunes de un evento academico
type BaseAcademicEvent struct {
	EventID   string          `json:"event_id"`
	Type      EventType       `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Actor     BaseActor       `json:"actor"`
	Context   AcademicContext `json:"context"`
}

func (e BaseAcademicEvent) Validate() error {
	if strings.TrimSpace(e.EventID) == "" {
		return ErrEmptyEventID
	}
	if !e.Type.IsValid() {
		return fmt.Errorf("%w: %s", ErrInvalidEventType, e.Type)
	}
	if e.Timestamp.IsZero() {
		return ErrZeroTimestamp
	}
	if err := e.Actor.Validate(); err != nil {
		return fmt.Errorf("invalid actor: %w", err)
	}
	if err := e.Context.Validate(); err != nil {
		return fmt.Errorf("invalid context: %w", err)
	}
	return nil
}

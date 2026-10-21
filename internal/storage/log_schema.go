package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"taller2-criptografia/internal/domain"
)

var (
	ErrEmptyLogID         = errors.New("log_id cannot be empty")
	ErrEmptySchemaVersion = errors.New("schema_version cannot be empty")
	ErrZeroCreatedAt      = errors.New("created_at cannot be zero")
	ErrEmptyEnvironment   = errors.New("environment cannot be empty")
	ErrEventCountMismatch = errors.New("total_events does not match events count")
	ErrNilEvent           = errors.New("event cannot be nil")
	ErrEmptyEventID       = errors.New("event_id cannot be empty")
	ErrInvalidEventType   = errors.New("invalid event type")
)

type LogMetadata struct {
	LogID         string    `json:"log_id"`
	SchemaVersion string    `json:"schema_version"` // "1.0.0"
	CreatedAt     time.Time `json:"created_at"`
	TotalEvents   int       `json:"total_events"`
	Environment   string    `json:"environment"` // "AUDIT_SIMULATION"
}

type ConsolidatedAcademicLog struct {
	Metadata LogMetadata           `json:"metadata"`
	Events   []domain.GenericEvent `json:"events"`
}

func NewConsolidatedAcademicLog(logID, environment string) *ConsolidatedAcademicLog {
	if environment == "" {
		environment = "AUDIT_SIMULATION"
	}
	return &ConsolidatedAcademicLog{
		Metadata: LogMetadata{
			LogID:         logID,
			SchemaVersion: "1.0.0",
			CreatedAt:     time.Now().UTC(),
			TotalEvents:   0,
			Environment:   environment,
		},
		Events: make([]domain.GenericEvent, 0),
	}
}

func (l *ConsolidatedAcademicLog) AddEvent(e domain.GenericEvent) {
	l.Events = append(l.Events, e)
	l.Metadata.TotalEvents = len(l.Events)
}

func (l *ConsolidatedAcademicLog) Validate() error {
	if strings.TrimSpace(l.Metadata.LogID) == "" {
		return ErrEmptyLogID
	}
	if strings.TrimSpace(l.Metadata.SchemaVersion) == "" {
		return ErrEmptySchemaVersion
	}
	if l.Metadata.CreatedAt.IsZero() {
		return ErrZeroCreatedAt
	}
	if strings.TrimSpace(l.Metadata.Environment) == "" {
		return ErrEmptyEnvironment
	}
	if l.Metadata.TotalEvents != len(l.Events) {
		return fmt.Errorf("%w: metadata=%d, actual=%d", ErrEventCountMismatch, l.Metadata.TotalEvents, len(l.Events))
	}
	for i, e := range l.Events {
		if e == nil {
			return fmt.Errorf("%w at index %d", ErrNilEvent, i)
		}
		if strings.TrimSpace(e.GetEventID()) == "" {
			return fmt.Errorf("%w at index %d", ErrEmptyEventID, i)
		}
		if !e.GetEventType().IsValid() {
			return fmt.Errorf("%w at index %d: %s", ErrInvalidEventType, i, e.GetEventType())
		}
	}
	return nil
}

func (l *ConsolidatedAcademicLog) UnmarshalJSON(data []byte) error {
	type rawLog struct {
		Metadata LogMetadata       `json:"metadata"`
		Events   []json.RawMessage `json:"events"`
	}
	var raw rawLog
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	l.Metadata = raw.Metadata
	l.Events = make([]domain.GenericEvent, len(raw.Events))

	for i, rawEvt := range raw.Events {
		var probe struct {
			EventType domain.EventType `json:"event_type"`
			Type      domain.EventType `json:"type"`
		}
		if err := json.Unmarshal(rawEvt, &probe); err != nil {
			return fmt.Errorf("failed to probe event type at index %d: %w", i, err)
		}

		eventType := probe.EventType
		if eventType == "" {
			eventType = probe.Type
		}

		switch eventType {
		case domain.EventTypeRegistration:
			var reg domain.GradeRegistrationEvent
			if err := json.Unmarshal(rawEvt, &reg); err != nil {
				return fmt.Errorf("failed to unmarshal registration event at index %d: %w", i, err)
			}
			l.Events[i] = &reg
		case domain.EventTypeModification:
			var mod domain.GradeModificationEvent
			if err := json.Unmarshal(rawEvt, &mod); err != nil {
				return fmt.Errorf("failed to unmarshal modification event at index %d: %w", i, err)
			}
			l.Events[i] = &mod
		default:
			return fmt.Errorf("unknown event type %q at index %d", eventType, i)
		}
	}
	return nil
}

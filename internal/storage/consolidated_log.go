package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"taller2-criptografia/internal/domain"
)

var (
	ErrNilConsolidatedLog = errors.New("consolidated log cannot be nil")
)

// ConsolidatedAcademicLog representa el log estructurado consolidado conforme al Paso 4 del taller.
// Agrupa la secuencia de eventos académicos antes de su hashing global y posterior cifrado.
type ConsolidatedAcademicLog struct {
	SchemaVersion string                `json:"schema_version,omitempty"`
	Events        []domain.GenericEvent `json:"events"`
	TotalEvents   int                   `json:"total_events,omitempty"`
}

// NewConsolidatedAcademicLog inicializa un log consolidado con los eventos académicos provistos.
func NewConsolidatedAcademicLog(events []domain.GenericEvent) *ConsolidatedAcademicLog {
	return &ConsolidatedAcademicLog{
		SchemaVersion: "1.0.0",
		Events:        events,
		TotalEvents:   len(events),
	}
}

// UnmarshalJSON deserializa el log instanciando los eventos concretos según su event_type.
func (l *ConsolidatedAcademicLog) UnmarshalJSON(data []byte) error {
	type rawLog struct {
		SchemaVersion string            `json:"schema_version"`
		Events        []json.RawMessage `json:"events"`
		TotalEvents   int               `json:"total_events"`
	}
	var raw rawLog
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	l.SchemaVersion = raw.SchemaVersion
	l.TotalEvents = raw.TotalEvents
	l.Events = make([]domain.GenericEvent, len(raw.Events))

	for i, rawEvt := range raw.Events {
		var probe struct {
			EventType domain.EventType `json:"event_type"`
			Type      domain.EventType `json:"type"`
		}
		if err := json.Unmarshal(rawEvt, &probe); err != nil {
			return fmt.Errorf("failed to probe event type at index %d: %w", i, err)
		}
		evType := probe.EventType
		if evType == "" {
			evType = probe.Type
		}
		switch evType {
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
			return fmt.Errorf("unknown event type %q at index %d", evType, i)
		}
	}
	if l.TotalEvents == 0 && len(l.Events) > 0 {
		l.TotalEvents = len(l.Events)
	}
	return nil
}

// SaveConsolidatedLogToFile serializa y persiste el log consolidado en disco con permisos restrictivos (0600).
func SaveConsolidatedLogToFile(path string, log *ConsolidatedAcademicLog) error {
	if log == nil {
		return ErrNilConsolidatedLog
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal consolidated log: %w", err)
	}
	dir := filepath.Dir(path)
	if err := EnsureOutputDirectory(dir); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadConsolidatedLogFromFile carga y deserializa el log consolidado desde disco.
func LoadConsolidatedLogFromFile(path string) (*ConsolidatedAcademicLog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read consolidated log file %s: %w", path, err)
	}
	var log ConsolidatedAcademicLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("failed to unmarshal consolidated log: %w", err)
	}
	return &log, nil
}


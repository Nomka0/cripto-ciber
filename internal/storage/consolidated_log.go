package storage

import (
	"taller2-criptografia/internal/domain"
)

// ConsolidatedAcademicLog representa el log estructurado consolidado conforme al Paso 4 del taller.
// Agrupa la secuencia de eventos académicos antes de su hashing global y posterior cifrado.
type ConsolidatedAcademicLog struct {
	SchemaVersion string                 `json:"schema_version,omitempty"`
	Events        []domain.GenericEvent  `json:"events"`
	TotalEvents   int                    `json:"total_events,omitempty"`
}

// NewConsolidatedAcademicLog inicializa un log consolidado con los eventos académicos provistos.
func NewConsolidatedAcademicLog(events []domain.GenericEvent) *ConsolidatedAcademicLog {
	return &ConsolidatedAcademicLog{
		SchemaVersion: "1.0.0",
		Events:        events,
		TotalEvents:   len(events),
	}
}

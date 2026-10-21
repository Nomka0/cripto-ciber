package audit

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"taller2-criptografia/internal/crypto"
	"taller2-criptografia/internal/storage"
)

// RecordAuditFinding detalla la auditoría individual de un evento académico,
// registrando el índice, identificador y hashes contrastados en caso de discrepancia.
type RecordAuditFinding struct {
	EventIndex     int    `json:"event_index"`
	EventID        string `json:"event_id"`
	ExpectedHash   string `json:"expected_hash"`
	CalculatedHash string `json:"calculated_hash"`
	IsValid        bool   `json:"is_valid"`
}

// RecordVerificationSummary consolida el resumen global de la auditoría registro a registro.
type RecordVerificationSummary struct {
	TotalEvents     int                  `json:"total_events"`
	ValidEvents     int                  `json:"valid_events"`
	CorruptedEvents int                  `json:"corrupted_events"`
	Findings        []RecordAuditFinding `json:"findings,omitempty"`
}

// VerifyAllRecords recorre cada uno de los eventos académicos presentes en el log y recalcula
// el hash de su payload para contrastarlo en tiempo constante contra el PayloadHash registrado.
// Permite identificar con precisión milimétrica qué registros específicos sufrieron adulteraciones.
func VerifyAllRecords(log *storage.ConsolidatedAcademicLog) RecordVerificationSummary {
	if log == nil || len(log.Events) == 0 {
		return RecordVerificationSummary{
			TotalEvents:     0,
			ValidEvents:     0,
			CorruptedEvents: 0,
			Findings:        nil,
		}
	}

	total := len(log.Events)
	valid := 0
	corrupted := 0
	findings := make([]RecordAuditFinding, 0)

	for i, event := range log.Events {
		if event == nil {
			corrupted++
			findings = append(findings, RecordAuditFinding{
				EventIndex:     i,
				EventID:        "",
				ExpectedHash:   "evento nulo",
				CalculatedHash: "",
				IsValid:        false,
			})
			continue
		}

		eventID := event.GetEventID()
		expectedHash := strings.TrimSpace(strings.ToLower(event.GetPayloadHash()))

		// Edge case: registro con PayloadHash vacío
		if expectedHash == "" {
			calcHash, _ := crypto.ComputePayloadHash(event)
			corrupted++
			findings = append(findings, RecordAuditFinding{
				EventIndex:     i,
				EventID:        eventID,
				ExpectedHash:   "ausencia de digest",
				CalculatedHash: calcHash,
				IsValid:        false,
			})
			continue
		}

		calculatedHash, err := crypto.ComputePayloadHash(event)
		if err != nil {
			corrupted++
			findings = append(findings, RecordAuditFinding{
				EventIndex:     i,
				EventID:        eventID,
				ExpectedHash:   expectedHash,
				CalculatedHash: fmt.Sprintf("error de cálculo: %v", err),
				IsValid:        false,
			})
			continue
		}

		calculatedClean := strings.TrimSpace(strings.ToLower(calculatedHash))

		// Comparación criptográfica segura en tiempo constante contra timing attacks
		if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(calculatedClean)) == 1 {
			valid++
		} else {
			corrupted++
			findings = append(findings, RecordAuditFinding{
				EventIndex:     i,
				EventID:        eventID,
				ExpectedHash:   expectedHash,
				CalculatedHash: calculatedClean,
				IsValid:        false,
			})
		}
	}

	return RecordVerificationSummary{
		TotalEvents:     total,
		ValidEvents:     valid,
		CorruptedEvents: corrupted,
		Findings:        findings,
	}
}

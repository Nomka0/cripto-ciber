package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditVerdict define el veredicto final emitido por el proceso de auditoría forense.
type AuditVerdict string

const (
	// VerdictSuccess certifica que el ciclo criptográfico preservó exactamente la información original.
	VerdictSuccess AuditVerdict = "INTEGRIDAD_PRESERVADA"

	// VerdictCorrupted indica que ocurrió al menos una discrepancia en el hash global o en registros individuales.
	VerdictCorrupted AuditVerdict = "DATOS_ALTERADOS_O_CORRUPTOS"
)

// AuditReport consolida los resultados de la verificación criptográfica global y registro por registro (Paso 10).
type AuditReport struct {
	Timestamp           time.Time                 `json:"timestamp"`
	GlobalComparison    IntegrityComparisonResult `json:"global_comparison"`
	RecordsVerification RecordVerificationSummary `json:"records_verification"`
	Verdict             AuditVerdict              `json:"verdict"`
	PreservationSuccess bool                      `json:"preservation_success"`
	ExecutionSummary    string                    `json:"execution_summary"`
}

// GenerateAuditReport consolida la comparación de hashes y la verificación de registros individuales
// evaluando la condición estricta: PreservationSuccess = comparison.Matches && records.CorruptedEvents == 0.
func GenerateAuditReport(comparison IntegrityComparisonResult, records RecordVerificationSummary) *AuditReport {
	preservationSuccess := comparison.Matches && records.CorruptedEvents == 0

	var verdict AuditVerdict
	var executionSummary string

	if preservationSuccess {
		verdict = VerdictSuccess
		executionSummary = fmt.Sprintf(
			"Auditoría exitosa: Integridad criptográfica preservada al 100%%. "+
				"El hash global original coincide exactamente con el descifrado y la totalidad de los %d registros son válidos.",
			records.TotalEvents,
		)
	} else {
		verdict = VerdictCorrupted
		var reasons []string
		if !comparison.Matches {
			reasons = append(reasons, fmt.Sprintf(
				"discrepancia en digest global (original: %s, descifrado: %s)",
				comparison.OriginalHash, comparison.DecryptedHash,
			))
		}
		if records.CorruptedEvents > 0 {
			reasons = append(reasons, fmt.Sprintf(
				"%d de %d registros presentan corrupción o ausencia de payload_hash",
				records.CorruptedEvents, records.TotalEvents,
			))
		}
		executionSummary = fmt.Sprintf(
			"Fallo de integridad forense: Se detectaron anomalías durante la auditoría. Causa(s): %s.",
			strings.Join(reasons, "; "),
		)
	}

	return &AuditReport{
		Timestamp:           time.Now().UTC(),
		GlobalComparison:    comparison,
		RecordsVerification: records,
		Verdict:             verdict,
		PreservationSuccess: preservationSuccess,
		ExecutionSummary:    executionSummary,
	}
}

// ToJSON serializa la estructura AuditReport a un slice de bytes en formato JSON indentado.
func (r *AuditReport) ToJSON() ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("audit report cannot be nil")
	}
	return json.MarshalIndent(r, "", "  ")
}

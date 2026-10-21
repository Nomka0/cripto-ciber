package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateAuditReport(t *testing.T) {
	const validHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	const alteredHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae"

	// 1. Criterio de Éxito Obligatorio: Matches=true y CorruptedEvents=0 -> INTEGRIDAD_PRESERVADA y PreservationSuccess=true
	t.Run("Criterio de Éxito: Integridad Preservada", func(t *testing.T) {
		globalComp := IntegrityComparisonResult{
			OriginalHash:  validHash,
			DecryptedHash: validHash,
			Matches:       true,
		}
		recordSummary := RecordVerificationSummary{
			TotalEvents:     100,
			ValidEvents:     100,
			CorruptedEvents: 0,
			Findings:        nil,
		}

		report := GenerateAuditReport(globalComp, recordSummary)

		if report == nil {
			t.Fatal("expected non-nil AuditReport")
		}

		if !report.PreservationSuccess {
			t.Errorf("expected PreservationSuccess to be true")
		}

		if report.Verdict != VerdictSuccess {
			t.Errorf("expected verdict %q, got %q", VerdictSuccess, report.Verdict)
		}

		if !strings.Contains(report.ExecutionSummary, "preservada al 100%") {
			t.Errorf("unexpected execution summary: %s", report.ExecutionSummary)
		}

		if report.Timestamp.IsZero() {
			t.Errorf("expected valid non-zero timestamp")
		}
	})

	// 2. Discrepancia global (Matches=false) aunque registros individuales estén íntegros
	t.Run("Discrepancia en Hash Global", func(t *testing.T) {
		globalComp := IntegrityComparisonResult{
			OriginalHash:  validHash,
			DecryptedHash: alteredHash,
			Matches:       false,
		}
		recordSummary := RecordVerificationSummary{
			TotalEvents:     50,
			ValidEvents:     50,
			CorruptedEvents: 0,
		}

		report := GenerateAuditReport(globalComp, recordSummary)

		if report.PreservationSuccess {
			t.Errorf("expected PreservationSuccess to be false due to global mismatch")
		}

		if report.Verdict != VerdictCorrupted {
			t.Errorf("expected verdict %q, got %q", VerdictCorrupted, report.Verdict)
		}

		if !strings.Contains(report.ExecutionSummary, "discrepancia en digest global") {
			t.Errorf("expected execution summary to mention global discrepancy, got: %s", report.ExecutionSummary)
		}
	})

	// 3. Hash global coincide pero hay 1 registro corrupto
	t.Run("Registro Individual Corrupto", func(t *testing.T) {
		globalComp := IntegrityComparisonResult{
			OriginalHash:  validHash,
			DecryptedHash: validHash,
			Matches:       true,
		}
		recordSummary := RecordVerificationSummary{
			TotalEvents:     100,
			ValidEvents:     99,
			CorruptedEvents: 1,
			Findings: []RecordAuditFinding{
				{
					EventIndex:     42,
					EventID:        "EVT-042",
					ExpectedHash:   validHash,
					CalculatedHash: alteredHash,
					IsValid:        false,
				},
			},
		}

		report := GenerateAuditReport(globalComp, recordSummary)

		if report.PreservationSuccess {
			t.Errorf("expected PreservationSuccess to be false due to corrupted event")
		}

		if report.Verdict != VerdictCorrupted {
			t.Errorf("expected verdict %q, got %q", VerdictCorrupted, report.Verdict)
		}

		if !strings.Contains(report.ExecutionSummary, "1 de 100 registros presentan corrupción") {
			t.Errorf("expected execution summary to detail corrupted records, got: %s", report.ExecutionSummary)
		}
	})

	// 4. Exportación a JSON (ToJSON)
	t.Run("Serialización ToJSON", func(t *testing.T) {
		globalComp := IntegrityComparisonResult{
			OriginalHash:  validHash,
			DecryptedHash: validHash,
			Matches:       true,
		}
		recordSummary := RecordVerificationSummary{
			TotalEvents:     10,
			ValidEvents:     10,
			CorruptedEvents: 0,
		}

		report := GenerateAuditReport(globalComp, recordSummary)
		jsonBytes, err := report.ToJSON()
		if err != nil {
			t.Fatalf("ToJSON failed: %v", err)
		}

		// Validar que deserialice correctamente
		var deserialized AuditReport
		if err := json.Unmarshal(jsonBytes, &deserialized); err != nil {
			t.Fatalf("failed to unmarshal generated JSON: %v", err)
		}

		if deserialized.Verdict != VerdictSuccess {
			t.Errorf("deserialized verdict mismatch: expected %s, got %s", VerdictSuccess, deserialized.Verdict)
		}
		if deserialized.PreservationSuccess != true {
			t.Errorf("deserialized preservation_success mismatch")
		}
		if deserialized.GlobalComparison.Matches != true {
			t.Errorf("deserialized matches mismatch")
		}
	})

	// 5. Manejo de nil en ToJSON
	t.Run("ToJSON en Nil", func(t *testing.T) {
		var nilReport *AuditReport
		if _, err := nilReport.ToJSON(); err == nil {
			t.Errorf("expected error calling ToJSON on nil report, got nil")
		}
	})
}

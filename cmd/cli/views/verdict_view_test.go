package views

import (
	"strings"
	"testing"
	"unicode/utf8"

	"taller2-criptografia/internal/audit"
	"taller2-criptografia/internal/orchestrator"
)

func TestFormatVerdictBox_True_Green(t *testing.T) {
	box := FormatVerdictBox(true)

	if !strings.HasPrefix(box, colorGreen) {
		t.Fatalf("expected green prefix %q, got %q", colorGreen, box[:10])
	}
	if !strings.HasSuffix(box, colorReset) {
		t.Fatalf("expected reset suffix %q", colorReset)
	}
	if !strings.Contains(box, "VERIFICACIÓN EXITOSA: INTEGRIDAD Y CONFIDENCIALIDAD PRESERVADAS") {
		t.Errorf("expected success title in box")
	}

	// Verificar alineación estricta de las líneas del recuadro
	lines := strings.Split(box, "\n")
	var boxLines []string
	for _, l := range lines {
		clean := strings.TrimPrefix(strings.TrimSuffix(l, colorReset), colorGreen)
		if strings.HasPrefix(clean, "  ┌") || strings.HasPrefix(clean, "  │") || strings.HasPrefix(clean, "  └") {
			boxLines = append(boxLines, clean)
		}
	}

	if len(boxLines) != 9 {
		t.Fatalf("expected 9 box lines (top, 7 content, bottom), got %d", len(boxLines))
	}

	expectedLen := utf8.RuneCountInString(boxLines[0])
	for i, line := range boxLines {
		if got := utf8.RuneCountInString(line); got != expectedLen {
			t.Errorf("box line %d width mismatch: got %d, expected %d: %q", i, got, expectedLen, line)
		}
	}
}

func TestFormatVerdictBox_False_Red(t *testing.T) {
	box := FormatVerdictBox(false)

	if !strings.HasPrefix(box, colorRed) {
		t.Fatalf("expected red prefix %q, got %q", colorRed, box[:10])
	}
	if !strings.HasSuffix(box, colorReset) {
		t.Fatalf("expected reset suffix %q", colorReset)
	}
	if !strings.Contains(box, "ALERTA DE SEGURIDAD: VIOLACIÓN DE INTEGRIDAD O CORRUPCIÓN") {
		t.Errorf("expected alert title in failure box")
	}

	lines := strings.Split(box, "\n")
	var boxLines []string
	for _, l := range lines {
		clean := strings.TrimPrefix(strings.TrimSuffix(l, colorReset), colorRed)
		if strings.HasPrefix(clean, "  ┌") || strings.HasPrefix(clean, "  │") || strings.HasPrefix(clean, "  └") {
			boxLines = append(boxLines, clean)
		}
	}

	if len(boxLines) != 9 {
		t.Fatalf("expected 9 box lines, got %d", len(boxLines))
	}

	expectedLen := utf8.RuneCountInString(boxLines[0])
	for i, line := range boxLines {
		if got := utf8.RuneCountInString(line); got != expectedLen {
			t.Errorf("failure box line %d width mismatch: got %d, expected %d: %q", i, got, expectedLen, line)
		}
	}
}

func TestFormatVerdictView_ArtifactPaths(t *testing.T) {
	res := &orchestrator.PipelineResults{
		PlaintextLogPath:   "/tmp/data/consolidated_log.json",
		CryptoMetadataPath: "/tmp/data/crypto_metadata.json",
		EncryptedLogPath:   "/tmp/data/consolidated_log.json.enc",
		DecryptedLogPath:   "/tmp/data/decrypted_log.json",
		PlaintextLogHash:   "abc123",
		DecryptedLogHash:   "abc123",
		AuditReport: &audit.AuditReport{
			PreservationSuccess: true,
			GlobalComparison: audit.IntegrityComparisonResult{
				Matches: true,
			},
		},
	}

	out := FormatVerdictView(res)
	if !strings.Contains(out, "/tmp/data/consolidated_log.json") {
		t.Errorf("missing plaintext path in output")
	}
	if !strings.Contains(out, "/tmp/data/crypto_metadata.json") {
		t.Errorf("missing crypto metadata path in output")
	}
	if !strings.Contains(out, "/tmp/data/consolidated_log.json.enc") {
		t.Errorf("missing encrypted log path in output")
	}
	if !strings.Contains(out, "/tmp/data/decrypted_log.json") {
		t.Errorf("missing decrypted log path in output")
	}
}

func TestFormatVerdictView_NilAndFallbacks(t *testing.T) {
	out := FormatVerdictView(nil)
	if !strings.Contains(out, "(no generado)") {
		t.Errorf("expected fallback for missing paths")
	}
	if !strings.Contains(out, colorRed) {
		t.Errorf("expected red color for nil/false result")
	}

	// Test RenderVerdictView directly
	printed := RenderVerdictView(nil)
	if printed != out {
		t.Errorf("RenderVerdictView output differs from FormatVerdictView")
	}
}

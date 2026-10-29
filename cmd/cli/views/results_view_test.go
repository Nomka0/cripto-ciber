package views

import (
	"strings"
	"testing"
	"unicode/utf8"

	"taller2-criptografia/internal/orchestrator"
)

func sampleResults() *orchestrator.PipelineResults {
	return &orchestrator.PipelineResults{
		TotalEvents:             500,
		RegistrationEventsCount: 330,
		ModificationEventsCount: 170,
		PlaintextLogHash:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		EncryptedLogHash:        "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
		DecryptedLogHash:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
}

func TestRenderResultsView(t *testing.T) {
	results := sampleResults()
	output := RenderResultsView(results)

	// Validar secciones principales
	expectedSections := []string{
		"================================================================================",
		"📊 RESULTADOS DEL TALLER DE PROTECCIÓN DE LOGS EN REPOSO",
		"[+] ESTADÍSTICAS DEL LOTE ACADÉMICO:",
		"• Total de eventos solicitados (Paso 1):   500",
		"• Eventos de Registro de Nota (Paso 2):    330 (66.0%)",
		"• Eventos de Modificación de Nota (Paso 2): 170 (34.0%)",
		"[+] TRAZABILIDAD CRIPTOGRÁFICA Y HASHES (SHA-256):",
		"1. Log Original (P5)",
		"2. Log Cifrado (P7)",
		"3. Log Descifrado(P9)",
		results.PlaintextLogHash,
		results.EncryptedLogHash,
		results.DecryptedLogHash,
	}

	for _, sec := range expectedSections {
		if !strings.Contains(output, sec) {
			t.Errorf("output does not contain expected section: %q", sec)
		}
	}

	// Validar alineación milimétrica de la tabla Unicode
	lines := strings.Split(output, "\n")
	var tableLines []string
	for _, l := range lines {
		if strings.HasPrefix(l, "  ┌") || strings.HasPrefix(l, "  │") ||
			strings.HasPrefix(l, "  ├") || strings.HasPrefix(l, "  └") {
			tableLines = append(tableLines, l)
		}
	}

	if len(tableLines) != 7 {
		t.Fatalf("expected 7 table lines, got %d", len(tableLines))
	}

	expectedLen := utf8.RuneCountInString(tableLines[0])
	for i, line := range tableLines {
		lineLen := utf8.RuneCountInString(line)
		if lineLen != expectedLen {
			t.Errorf("table line %d has width %d, expected %d: %q", i, lineLen, expectedLen, line)
		}

		// Validar que el separador intermedio de columna esté en la misma posición en todas las filas
		runes := []rune(line)
		colSeparatorPos := 2 + 1 + col1Width // "  " + borde izquierdo (1) + 23 runes
		sepChar := string(runes[colSeparatorPos])
		if !strings.ContainsAny(sepChar, "┬┼│┴") {
			t.Errorf("table line %d has unexpected column separator %q at position %d", i, sepChar, colSeparatorPos)
		}
	}
}

func TestRenderResultsView_TruncatedWidth(t *testing.T) {
	results := sampleResults()
	const narrowWidth = 80
	output := FormatResultsViewWithWidth(results, narrowWidth)

	lines := strings.Split(output, "\n")
	var tableLines []string
	for _, l := range lines {
		if strings.HasPrefix(l, "  ┌") || strings.HasPrefix(l, "  │") ||
			strings.HasPrefix(l, "  ├") || strings.HasPrefix(l, "  └") {
			tableLines = append(tableLines, l)
		}
	}

	if len(tableLines) != 7 {
		t.Fatalf("expected 7 table lines in narrow view, got %d", len(tableLines))
	}

	expectedLen := utf8.RuneCountInString(tableLines[0])
	if expectedLen > narrowWidth {
		t.Errorf("table line length %d exceeds requested terminal width %d", expectedLen, narrowWidth)
	}

	for i, line := range tableLines {
		lineLen := utf8.RuneCountInString(line)
		if lineLen != expectedLen {
			t.Errorf("narrow table line %d width mismatch: got %d, expected %d", i, lineLen, expectedLen)
		}
	}

	// En ancho estrecho los hashes deben estar truncados con "..."
	if !strings.Contains(output, "...") {
		t.Errorf("expected hash truncation with '...' in narrow terminal view")
	}
}

func TestRenderResultsView_NilResults(t *testing.T) {
	out := RenderResultsView(nil)
	if !strings.Contains(out, "[!]") {
		t.Errorf("expected warning for nil results, got: %q", out)
	}
}

func TestRenderResultsView_ZeroEvents(t *testing.T) {
	zeroRes := &orchestrator.PipelineResults{
		TotalEvents:             0,
		RegistrationEventsCount: 0,
		ModificationEventsCount: 0,
	}
	out := FormatResultsViewWithWidth(zeroRes, 96)
	if !strings.Contains(out, "0 (0.0%)") {
		t.Errorf("expected 0.0%% for zero events, got: %q", out)
	}
}

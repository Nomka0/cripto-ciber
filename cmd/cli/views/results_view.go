package views

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"

	"taller2-criptografia/internal/orchestrator"
)

const (
	defaultTableWidth = 94
	col1Width         = 23
	bannerWidth       = 80
)

// RenderResultsView imprime en stdout la pantalla de presentación de resultados del Paso 10
// y retorna la cadena formateada.
func RenderResultsView(results *orchestrator.PipelineResults) string {
	output := FormatResultsView(results)
	fmt.Print(output)
	return output
}

// FormatResultsView genera la vista formateada detectando el ancho actual de la terminal.
func FormatResultsView(results *orchestrator.PipelineResults) string {
	return FormatResultsViewWithWidth(results, getTerminalWidth())
}

// FormatResultsViewWithWidth genera la vista formateada para un ancho específico de terminal.
func FormatResultsViewWithWidth(results *orchestrator.PipelineResults, termWidth int) string {
	if results == nil {
		return "[!] No hay resultados disponibles para presentar.\n"
	}

	var b strings.Builder

	// Banner superior
	divider := strings.Repeat("=", bannerWidth)
	b.WriteString(divider + "\n")
	b.WriteString("          📊 RESULTADOS DEL TALLER DE PROTECCIÓN DE LOGS EN REPOSO\n")
	b.WriteString(divider + "\n")

	// Estadísticas del lote
	regPct := 0.0
	modPct := 0.0
	if results.TotalEvents > 0 {
		regPct = float64(results.RegistrationEventsCount) / float64(results.TotalEvents) * 100.0
		modPct = float64(results.ModificationEventsCount) / float64(results.TotalEvents) * 100.0
	}

	b.WriteString("[+] ESTADÍSTICAS DEL LOTE ACADÉMICO:\n")
	fmt.Fprintf(&b, "    • Total de eventos solicitados (Paso 1):   %d\n", results.TotalEvents)
	fmt.Fprintf(&b, "    • Eventos de Registro de Nota (Paso 2):    %d (%.1f%%)\n", results.RegistrationEventsCount, regPct)
	fmt.Fprintf(&b, "    • Eventos de Modificación de Nota (Paso 2): %d (%.1f%%)\n", results.ModificationEventsCount, modPct)
	b.WriteString("\n")

	// Tabla de trazabilidad criptográfica
	b.WriteString("[+] TRAZABILIDAD CRIPTOGRÁFICA Y HASHES (SHA-256):\n")

	col2Width := 66
	if termWidth < defaultTableWidth && termWidth > 0 {
		col2Width = termWidth - 28 // 2 espacios + 3 bordes + 23 col1
		if col2Width < 30 {
			col2Width = 30
		}
	}

	headerCol2 := " RESUMEN CRIPTOGRÁFICO (DIGEST HEX)"
	if col2Width-2 < utf8.RuneCountInString("RESUMEN CRIPTOGRÁFICO (DIGEST HEX)") {
		headerCol2 = " " + truncateString("RESUMEN CRIPTOGRÁFICO (DIGEST HEX)", col2Width-2)
	}

	// Bordes y filas de la tabla
	topBorder := fmt.Sprintf("  ┌%s┬%s┐\n", strings.Repeat("─", col1Width), strings.Repeat("─", col2Width))
	headerRow := fmt.Sprintf("  │%s│%s│\n", padRight(" ETAPA", col1Width), padRight(headerCol2, col2Width))
	separator := fmt.Sprintf("  ├%s┼%s┤\n", strings.Repeat("─", col1Width), strings.Repeat("─", col2Width))
	row1 := fmt.Sprintf("  │%s│%s│\n", padRight(" 1. Log Original (P5)", col1Width), padRight(" "+formatHash(results.PlaintextLogHash, col2Width-2)+" ", col2Width))
	row2 := fmt.Sprintf("  │%s│%s│\n", padRight(" 2. Log Cifrado (P7)", col1Width), padRight(" "+formatHash(results.EncryptedLogHash, col2Width-2)+" ", col2Width))
	row3 := fmt.Sprintf("  │%s│%s│\n", padRight(" 3. Log Descifrado(P9)", col1Width), padRight(" "+formatHash(results.DecryptedLogHash, col2Width-2)+" ", col2Width))
	botBorder := fmt.Sprintf("  └%s┴%s┘\n", strings.Repeat("─", col1Width), strings.Repeat("─", col2Width))

	b.WriteString(topBorder)
	b.WriteString(headerRow)
	b.WriteString(separator)
	b.WriteString(row1)
	b.WriteString(row2)
	b.WriteString(row3)
	b.WriteString(botBorder)

	return b.String()
}

func getTerminalWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	if w, _, err := term.GetSize(int(os.Stdin.Fd())); err == nil && w > 0 {
		return w
	}
	return defaultTableWidth
}

func padRight(s string, width int) string {
	count := utf8.RuneCountInString(s)
	if count >= width {
		return s
	}
	return s + strings.Repeat(" ", width-count)
}

func formatHash(hash string, maxLen int) string {
	trimmed := strings.TrimSpace(hash)
	rCount := utf8.RuneCountInString(trimmed)
	if rCount <= maxLen {
		return trimmed
	}
	if maxLen < 7 {
		runes := []rune(trimmed)
		return string(runes[:maxLen])
	}
	prefixLen := (maxLen - 3) / 2
	suffixLen := maxLen - 3 - prefixLen
	runes := []rune(trimmed)
	return string(runes[:prefixLen]) + "..." + string(runes[len(runes)-suffixLen:])
}

func truncateString(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

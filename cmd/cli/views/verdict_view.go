package views

import (
	"fmt"
	"strings"

	"taller2-criptografia/internal/orchestrator"
)

const (
	verdictBoxWidth = 72
	colorGreen      = "\033[32m"
	colorRed        = "\033[31m"
	colorReset      = "\033[0m"
)

// RenderVerdictView imprime el veredicto de seguridad y las rutas de artefactos en stdout.
func RenderVerdictView(results *orchestrator.PipelineResults) string {
	output := FormatVerdictView(results)
	fmt.Print(output)
	return output
}

// FormatVerdictView construye la vista completa de veredicto y rutas a partir de los resultados del pipeline.
func FormatVerdictView(results *orchestrator.PipelineResults) string {
	if results == nil {
		return FormatVerdict(false, "", "", "", "")
	}
	return FormatVerdict(
		results.IntegrityMatches(),
		results.PlaintextLogPath,
		results.CryptoMetadataPath,
		results.EncryptedLogPath,
		results.DecryptedLogPath,
	)
}

// RenderVerdict imprime en stdout el veredicto para un estado de integridad y rutas explícitas.
func RenderVerdict(integrityMatches bool, plaintextPath, metadataPath, encryptedPath, decryptedPath string) string {
	output := FormatVerdict(integrityMatches, plaintextPath, metadataPath, encryptedPath, decryptedPath)
	fmt.Print(output)
	return output
}

// FormatVerdictBox genera la caja del veredicto con caracteres Unicode y coloreado ANSI:
// verde (\033[32m) si IntegrityMatches == true, rojo (\033[31m) si IntegrityMatches == false.
func FormatVerdictBox(integrityMatches bool) string {
	var b strings.Builder
	color := colorGreen
	lines := []string{
		"  [ ✔ ] VERIFICACIÓN EXITOSA: INTEGRIDAD Y CONFIDENCIALIDAD PRESERVADAS",
		"",
		"  • Confidencialidad: El log fue cifrado con AES-256-GCM nativo.",
		"  • Integridad Global: Hash Original == Hash Descifrado (100% Match).",
		"  • Integridad Granular: Los payloads de cada registro son válidos.",
		"  • Conclusión: El proceso de cifrado y descifrado preservó fielmente",
		"    la información original sin pérdida ni alteración de datos.",
	}

	if !integrityMatches {
		color = colorRed
		lines = []string{
			"  [ ✘ ] ALERTA DE SEGURIDAD: VIOLACIÓN DE INTEGRIDAD O CORRUPCIÓN",
			"",
			"  • Confidencialidad: El log fue procesado con AES-256-GCM.",
			"  • Integridad Global: DISCREPANCIA DETECTADA (Hashes no coinciden).",
			"  • Integridad Granular: Se detectaron registros corruptos o inválidos.",
			"  • Conclusión: El proceso no preservó la integridad criptográfica",
			"    de la información original.",
		}
	}

	b.WriteString(color)
	fmt.Fprintf(&b, "  ┌%s┐\n", strings.Repeat("─", verdictBoxWidth))
	for _, l := range lines {
		fmt.Fprintf(&b, "  │%s│\n", padRight(l, verdictBoxWidth))
	}
	fmt.Fprintf(&b, "  └%s┘\n", strings.Repeat("─", verdictBoxWidth))
	b.WriteString(colorReset)

	return b.String()
}

// FormatVerdict genera la sección del veredicto junto con las rutas físicas de los artefactos.
func FormatVerdict(integrityMatches bool, plaintextPath, metadataPath, encryptedPath, decryptedPath string) string {
	var b strings.Builder
	b.WriteString("\n[+] VEREDICTO DE SEGURIDAD Y PRESERVACIÓN:\n")
	b.WriteString(FormatVerdictBox(integrityMatches))

	b.WriteString("\n[+] ARTEFACTOS Y RUTAS FÍSICAS GENERADAS:\n")
	fmt.Fprintf(&b, "    • Log Original (P5):        %s\n", defaultPathOr(plaintextPath, "(no generado)"))
	fmt.Fprintf(&b, "    • Metadatos Cripto (P6/7):  %s\n", defaultPathOr(metadataPath, "(no generado)"))
	fmt.Fprintf(&b, "    • Log Cifrado (P7):         %s\n", defaultPathOr(encryptedPath, "(no generado)"))
	fmt.Fprintf(&b, "    • Log Descifrado (P9):      %s\n", defaultPathOr(decryptedPath, "(no generado)"))

	return b.String()
}

func defaultPathOr(path, fallback string) string {
	if strings.TrimSpace(path) == "" {
		return fallback
	}
	return path
}

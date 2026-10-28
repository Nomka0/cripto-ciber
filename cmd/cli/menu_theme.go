package main

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
)

// Secuencias ANSI del tema visual de la CLI.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// Title imprime un encabezado de sección resaltado.
func Title(text string) {
	fmt.Printf("\n%s%s🔐 %s%s\n", ansiBold, ansiCyan, text, ansiReset)
}

// Success imprime un mensaje de éxito en verde.
func Success(format string, a ...any) {
	fmt.Printf("%s✔ %s%s\n", ansiGreen, fmt.Sprintf(format, a...), ansiReset)
}

// Warn imprime una advertencia en amarillo.
func Warn(format string, a ...any) {
	fmt.Printf("%s⚠ %s%s\n", ansiYellow, fmt.Sprintf(format, a...), ansiReset)
}

// Error imprime un mensaje de error en rojo.
func Error(format string, a ...any) {
	fmt.Printf("%s✖ %s%s\n", ansiRed, fmt.Sprintf(format, a...), ansiReset)
}

// SurveyTheme aplica los íconos y colores del tema a los prompts de survey.
// Uso: survey.AskOne(prompt, &answer, SurveyTheme())
func SurveyTheme() survey.AskOpt {
	return survey.WithIcons(func(icons *survey.IconSet) {
		icons.Question = survey.Icon{Text: "🔐", Format: "cyan+b"}
		icons.SelectFocus = survey.Icon{Text: "❯", Format: "cyan+b"}
		icons.Error = survey.Icon{Text: "✖", Format: "red+b"}
		icons.Help = survey.Icon{Text: "ℹ", Format: "yellow"}
		icons.MarkedOption = survey.Icon{Text: "◉", Format: "green+b"}
		icons.UnmarkedOption = survey.Icon{Text: "◯", Format: "default"}
	})
}

package main

import (
	"errors"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
)

// MaxEventVolume es el límite superior recomendado para la simulación.
const MaxEventVolume = 100000

var (
	ErrVolumeNotPositive = errors.New("debe ingresar un número entero mayor que 0")
	ErrVolumeTooLarge    = errors.New("el límite recomendado para la simulación es 100,000 eventos")
)

// ParseEventVolume convierte y valida el volumen N: entero, 0 < N <= MaxEventVolume.
// Es la única regla de validación, compartida por el prompt interactivo y el flag --events.
func ParseEventVolume(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, ErrVolumeNotPositive
	}
	if n > MaxEventVolume {
		return 0, ErrVolumeTooLarge
	}
	return n, nil
}

// ValidateEventVolume adapta ParseEventVolume a la firma de survey.Validator.
func ValidateEventVolume(val any) error {
	s, ok := val.(string)
	if !ok {
		return errors.New("entrada no válida")
	}
	_, err := ParseEventVolume(s)
	return err
}

// PromptEventVolume solicita el volumen de eventos (Paso 1). Si la entrada es inválida,
// survey muestra el error y vuelve a preguntar sin salir del prompt.
func PromptEventVolume() (int, error) {
	var volumeStr string
	prompt := &survey.Input{
		Message: "¿Cuántos eventos académicos desea generar? (Ej: 100, 1000):",
		Default: "50",
	}
	if err := survey.AskOne(prompt, &volumeStr, survey.WithValidator(ValidateEventVolume), SurveyTheme()); err != nil {
		return 0, err
	}
	return ParseEventVolume(volumeStr)
}

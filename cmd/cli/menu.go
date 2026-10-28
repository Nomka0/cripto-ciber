package main

import (
	"errors"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
)

type MenuOption string

const (
	OptionFullPipeline   MenuOption = "1. Ejecutar Flujo Completo (Pasos 1 al 10)"
	OptionDefineVolume   MenuOption = "2. Paso 1: Definir volumen de eventos"
	OptionGenerateEvents MenuOption = "3. Pasos 2-4: Generar eventos y log consolidado"
	OptionEncryptLog     MenuOption = "4. Pasos 5-7: Hashear y Cifrar log en reposo"
	OptionDecryptLog     MenuOption = "5. Pasos 8-9: Descifrar y validar integridad"
	OptionAuditReport    MenuOption = "6. Paso 10: Ver reporte de auditoría y comparativa de hashes"
	OptionExit           MenuOption = "7. Salir"
)

var menuOptions = []MenuOption{
	OptionFullPipeline, OptionDefineVolume, OptionGenerateEvents,
	OptionEncryptLog, OptionDecryptLog, OptionAuditReport, OptionExit,
}

// MenuHandlers asocia cada opción del menú con la acción que ejecuta.
type MenuHandlers map[MenuOption]func() error

// ShowMainMenu despliega el selector interactivo (flechas ↑/↓ + Enter) y retorna la opción elegida.
// Ctrl+C retorna terminal.InterruptErr.
func ShowMainMenu() (MenuOption, error) {
	labels := make([]string, len(menuOptions))
	for i, o := range menuOptions {
		labels[i] = string(o)
	}

	var choice string
	prompt := &survey.Select{
		Message:  "¿Qué operación desea ejecutar?",
		Options:  labels,
		PageSize: len(labels),
	}
	if err := survey.AskOne(prompt, &choice, SurveyTheme()); err != nil {
		return "", err
	}
	return MenuOption(choice), nil
}

// RunMenuLoop mantiene la aplicación abierta hasta elegir "Salir" o presionar Ctrl+C.
// El error de un handler se muestra sin cerrar la aplicación.
func RunMenuLoop(ask func() (MenuOption, error), handlers MenuHandlers) error {
	for {
		option, err := ask()
		if errors.Is(err, terminal.InterruptErr) {
			Warn("Operación cancelada por el usuario (Ctrl+C)")
			return nil
		}
		if err != nil {
			return err
		}
		if option == OptionExit {
			Success("Hasta luego")
			return nil
		}

		handler, ok := handlers[option]
		if !ok {
			Warn("Opción no implementada: %s", option)
			continue
		}
		if err := handler(); err != nil {
			Error("%s: %v", option, err)
		}
	}
}

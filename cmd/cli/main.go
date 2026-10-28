package main

import (
	"flag"
	"fmt"
	"os"
)

const appVersion = "0.1.0"

func main() {
	showVersion := flag.Bool("version", false, "muestra la versión y termina")
	auto := flag.Bool("auto", false, "ejecuta el flujo completo (Pasos 1 al 10) sin menú")
	var eventsFlag string
	flag.StringVar(&eventsFlag, "events", "", "volumen de eventos N a generar (0 < N <= 100000)")
	flag.StringVar(&eventsFlag, "n", "", "atajo de --events")
	flag.Parse()

	if *showVersion {
		fmt.Printf("taller2-criptografia CLI v%s\n", appVersion)
		return
	}

	// Paso 1: el volumen puede llegar por flag (scripts) o por prompt interactivo (opción 2 del menú).
	volume := 0
	if eventsFlag != "" {
		n, err := ParseEventVolume(eventsFlag)
		if err != nil {
			Error("--events %q: %v", eventsFlag, err)
			os.Exit(2)
		}
		volume = n
	}

	Title("Protección de Logs Estructurados en Reposo")

	// honey: el resto de handlers (y el uso de volume) se conectan en US-11 (pipeline de ejecución).
	handlers := MenuHandlers{
		OptionDefineVolume: func() error {
			n, err := PromptEventVolume()
			if err != nil {
				return err
			}
			volume = n
			Success("Volumen definido: %d eventos", volume)
			return nil
		},
	}

	ask := ShowMainMenu
	if *auto {
		ask = autoAsk()
	}

	if err := RunMenuLoop(ask, handlers); err != nil {
		Error("%v", err)
		os.Exit(1)
	}
}

// autoAsk responde "Flujo Completo" y luego "Salir": modo no interactivo para demostraciones.
func autoAsk() func() (MenuOption, error) {
	answers := []MenuOption{OptionFullPipeline, OptionExit}
	return func() (MenuOption, error) {
		next := answers[0]
		answers = answers[1:]
		return next, nil
	}
}

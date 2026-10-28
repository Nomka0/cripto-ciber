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
	flag.Parse()

	if *showVersion {
		fmt.Printf("taller2-criptografia CLI v%s\n", appVersion)
		return
	}

	Title("Protección de Logs Estructurados en Reposo")

	// honey: los handlers de cada paso se conectan en US-11 (pipeline de ejecución).
	handlers := MenuHandlers{}

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

package main

import (
	"flag"
	"fmt"
)

const appVersion = "0.1.0"

func main() {
	showVersion := flag.Bool("version", false, "muestra la versión y termina")
	flag.Parse()

	if *showVersion {
		fmt.Printf("taller2-criptografia CLI v%s\n", appVersion)
		return
	}

	Title("Protección de Logs Estructurados en Reposo")
	Success("CLI inicializada (survey/v2)")
}

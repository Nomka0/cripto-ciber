package main

import (
	"flag"
	"fmt"
	"os"

	"taller2-criptografia/cmd/cli/views"
	"taller2-criptografia/internal/pipeline"
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

	orch := pipeline.NewPipelineOrchestrator("", nil)

	handlers := MenuHandlers{
		OptionFullPipeline: func() error {
			if volume <= 0 {
				n, err := PromptEventVolume()
				if err != nil {
					return err
				}
				volume = n
			}
			Success("Iniciando ejecución del flujo completo con %d eventos...", volume)
			res, err := orch.Run(volume)
			if err != nil {
				return err
			}
			views.RenderResultsView(res)
			Success("Flujo completo ejecutado con éxito. Preservación: %v", res.AuditReport.PreservationSuccess)
			return nil
		},
		OptionDefineVolume: func() error {
			n, err := PromptEventVolume()
			if err != nil {
				return err
			}
			volume = n
			Success("Volumen definido: %d eventos", volume)
			return nil
		},
		OptionGenerateEvents: func() error {
			if volume <= 0 {
				n, err := PromptEventVolume()
				if err != nil {
					return err
				}
				volume = n
			}
			log, reg, mod, err := orch.GenerateAndConsolidate(volume)
			if err != nil {
				return err
			}
			Success("Generados y consolidados %d eventos (%d registros, %d modificaciones)", log.TotalEvents, reg, mod)
			return nil
		},
		OptionEncryptLog: func() error {
			plainDigest, _, encDigest, err := orch.EncryptAndHash()
			if err != nil {
				return err
			}
			Success("Log cifrado en reposo. Hash claro: %s... | Hash cifrado: %s...", plainDigest.Digest[:16], encDigest.Digest[:16])
			return nil
		},
		OptionDecryptLog: func() error {
			_, decDigest, err := orch.DecryptAndHash()
			if err != nil {
				return err
			}
			Success("Log descifrado exitosamente. Hash descifrado: %s...", decDigest.Digest[:16])
			return nil
		},
		OptionAuditReport: func() error {
			report, err := orch.Audit()
			if err != nil {
				return err
			}
			Success("Auditoría finalizada. Veredicto: %s (Preservación: %v)", report.Verdict, report.PreservationSuccess)
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

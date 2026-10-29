package orchestrator

import "taller2-criptografia/internal/pipeline"

// PipelineResults es un alias para pipeline.PipelineResult conforme a la especificación de vistas CLI.
type PipelineResults = pipeline.PipelineResult

// PipelineResult es un alias para pipeline.PipelineResult.
type PipelineResult = pipeline.PipelineResult

// PipelineOrchestrator es un alias para pipeline.PipelineOrchestrator.
type PipelineOrchestrator = pipeline.PipelineOrchestrator

// StepListener es un alias para pipeline.StepListener.
type StepListener = pipeline.StepListener

// NewPipelineOrchestrator reexporta el constructor de pipeline.
var NewPipelineOrchestrator = pipeline.NewPipelineOrchestrator

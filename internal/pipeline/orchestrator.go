package pipeline

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"

	"taller2-criptografia/internal/audit"
	"taller2-criptografia/internal/crypto"
	"taller2-criptografia/internal/domain"
	"taller2-criptografia/internal/generator"
	"taller2-criptografia/internal/storage"
)

var (
	ErrInvalidVolume        = errors.New("event volume must be greater than zero")
	ErrPlaintextLogNotFound = errors.New("plaintext log not found: run generation first (Steps 2-4)")
	ErrEncryptedLogNotFound = errors.New("encrypted log or metadata not found: run encryption first (Steps 5-7)")
	ErrDecryptedLogNotFound = errors.New("decrypted log not found: run decryption first (Steps 8-9)")
)

// PipelineResult consolida los resultados y artefactos de la ejecución integral (Pasos 1 al 10).
type PipelineResult struct {
	TotalEvents             int                        `json:"total_events"`
	RegistrationEventsCount int                        `json:"registration_events_count"`
	ModificationEventsCount int                        `json:"modification_events_count"`
	PlaintextLogPath        string                     `json:"plaintext_log_path"`
	PlaintextLogHash        string                     `json:"plaintext_log_hash"`
	EncryptedLogPath        string                     `json:"encrypted_log_path"`
	EncryptedLogHash        string                     `json:"encrypted_log_hash"`
	CryptoMetadataPath      string                     `json:"crypto_metadata_path"`
	DecryptedLogPath        string                     `json:"decrypted_log_path"`
	DecryptedLogHash        string                     `json:"decrypted_log_hash"`
	AuditReport             *audit.AuditReport         `json:"audit_report"`
}

// PipelineResults es un alias para PipelineResult para compatibilidad.
type PipelineResults = PipelineResult

// PipelineOrchestrator coordina el ciclo de vida completo de protección de logs en reposo.
type PipelineOrchestrator struct {
	outputDir string
	generator *generator.EventOrchestrator
	hasher    crypto.GlobalHasher
}

// NewPipelineOrchestrator inicializa un orquestador con directorio base de artefactos y PRNG opcional.
func NewPipelineOrchestrator(outputDir string, r *rand.Rand) *PipelineOrchestrator {
	if outputDir == "" {
		outputDir = storage.DefaultOutputDir
	}
	return &PipelineOrchestrator{
		outputDir: outputDir,
		generator: generator.NewEventOrchestrator(nil, r),
		hasher:    crypto.NewGlobalHasher(),
	}
}

// OutputDir retorna el directorio donde residen los artefactos.
func (p *PipelineOrchestrator) OutputDir() string {
	return p.outputDir
}

// GenerateAndConsolidate ejecuta los Pasos 2, 3 y 4:
// genera N eventos, calcula e inyecta su payload_hash y persiste academic_log.json.
func (p *PipelineOrchestrator) GenerateAndConsolidate(volume int) (*storage.ConsolidatedAcademicLog, int, int, error) {
	if volume <= 0 {
		return nil, 0, 0, ErrInvalidVolume
	}

	if err := storage.EnsureOutputDirectory(p.outputDir); err != nil {
		return nil, 0, 0, err
	}

	rawSequence, err := p.generator.GenerateSequence(volume)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to generate events: %w", err)
	}

	events := make([]domain.GenericEvent, len(rawSequence))
	regCount, modCount := 0, 0

	for i, raw := range rawSequence {
		evt, ok := raw.(domain.GenericEvent)
		if !ok {
			return nil, 0, 0, fmt.Errorf("event at index %d does not implement GenericEvent", i)
		}

		// Paso 3: Hash del payload sin circularidad
		if err := crypto.SignEventPayload(evt); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to sign event %s: %w", evt.GetEventID(), err)
		}

		events[i] = evt
		switch evt.GetEventType() {
		case domain.EventTypeRegistration:
			regCount++
		case domain.EventTypeModification:
			modCount++
		}
	}

	// Paso 4: Construcción del log consolidado
	consolidated := storage.NewConsolidatedAcademicLog(events)
	plainPath := storage.GetPlaintextLogPath(p.outputDir)
	if err := storage.SaveConsolidatedLogToFile(plainPath, consolidated); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to save plaintext log: %w", err)
	}

	return consolidated, regCount, modCount, nil
}

// EncryptAndHash ejecuta los Pasos 5, 6 y 7:
// hashea el log en claro, cifra en reposo (AES-256-GCM + metadata) y hashea el ciphertext.
func (p *PipelineOrchestrator) EncryptAndHash() (*crypto.FileDigestResult, *crypto.EncryptionArtifacts, *crypto.FileDigestResult, error) {
	plainPath := storage.GetPlaintextLogPath(p.outputDir)
	if _, err := os.Stat(plainPath); err != nil {
		return nil, nil, nil, ErrPlaintextLogNotFound
	}

	// Paso 5: Hash del log en claro (academic_log.json.sha256)
	plainWitness := storage.GetPlaintextLogHashPath(p.outputDir)
	plainDigest, err := p.hasher.HashPlaintextLog(plainPath, plainWitness)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to hash plaintext log: %w", err)
	}

	// Paso 6: Cifrado en reposo con llave y nonce frescos
	artifacts, err := crypto.EncryptLogFile(plainPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt log file: %w", err)
	}

	encPath := storage.GetEncryptedLogPath(p.outputDir)
	if err := storage.SaveCiphertext(encPath, artifacts.Ciphertext); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to save ciphertext: %w", err)
	}

	metaPath := storage.GetCryptoMetadataPath(p.outputDir)
	if err := storage.SaveCryptoMetadata(metaPath, artifacts.Key, artifacts.Nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to save crypto metadata: %w", err)
	}

	// Paso 7: Hash del log cifrado (academic_log.enc.sha256)
	encWitness := storage.GetEncryptedLogHashPath(p.outputDir)
	encDigest, err := p.hasher.HashEncryptedLog(encPath, encWitness)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to hash encrypted log: %w", err)
	}

	return &plainDigest, artifacts, &encDigest, nil
}

// DecryptAndHash ejecuta los Pasos 8 y 9:
// descifra academic_log.enc recuperando academic_log_decrypted.json y calcula su hash SHA-256.
func (p *PipelineOrchestrator) DecryptAndHash() ([]byte, *crypto.FileDigestResult, error) {
	encPath := storage.GetEncryptedLogPath(p.outputDir)
	metaPath := storage.GetCryptoMetadataPath(p.outputDir)
	if _, err := os.Stat(encPath); err != nil {
		return nil, nil, ErrEncryptedLogNotFound
	}
	if _, err := os.Stat(metaPath); err != nil {
		return nil, nil, ErrEncryptedLogNotFound
	}

	decPath := storage.GetDecryptedLogPath(p.outputDir)

	// Paso 8: Descifrado autenticado y recuperación
	plaintext, err := crypto.RestoreDecryptedLogFile(encPath, metaPath, decPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt log file: %w", err)
	}

	// Paso 9: Hash del log descifrado (academic_log_decrypted.sha256)
	decWitness := storage.GetDecryptedLogHashPath(p.outputDir)
	decDigest, err := p.hasher.HashDecryptedLog(decPath, true, decWitness)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash decrypted log: %w", err)
	}

	return plaintext, &decDigest, nil
}

// Audit ejecuta el Paso 10:
// compara en tiempo constante los hashes global original y descifrado, audita los registros individuales y emite el veredicto.
func (p *PipelineOrchestrator) Audit() (*audit.AuditReport, error) {
	plainPath := storage.GetPlaintextLogPath(p.outputDir)
	decPath := storage.GetDecryptedLogPath(p.outputDir)

	if _, err := os.Stat(plainPath); err != nil {
		return nil, ErrPlaintextLogNotFound
	}
	if _, err := os.Stat(decPath); err != nil {
		return nil, ErrDecryptedLogNotFound
	}

	origHash, err := p.hasher.HashFile(plainPath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash of original log: %w", err)
	}

	decHash, err := p.hasher.HashFile(decPath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash of decrypted log: %w", err)
	}

	comp := audit.CompareHashes(origHash, decHash)

	decryptedLog, err := storage.LoadConsolidatedLogFromFile(decPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load decrypted log for record verification: %w", err)
	}

	recSummary := audit.VerifyAllRecords(decryptedLog)
	report := audit.GenerateAuditReport(comp, recSummary)

	return report, nil
}

// Run ejecuta el flujo completo de los Pasos 1 al 10 de manera secuencial y determinista.
func (p *PipelineOrchestrator) Run(volume int) (*PipelineResult, error) {
	if volume <= 0 {
		return nil, ErrInvalidVolume
	}

	// Pasos 2-4
	log, regCount, modCount, err := p.GenerateAndConsolidate(volume)
	if err != nil {
		return nil, err
	}

	// Pasos 5-7
	plainDigest, _, encDigest, err := p.EncryptAndHash()
	if err != nil {
		return nil, err
	}

	// Pasos 8-9
	_, decDigest, err := p.DecryptAndHash()
	if err != nil {
		return nil, err
	}

	// Paso 10
	auditReport, err := p.Audit()
	if err != nil {
		return nil, err
	}

	return &PipelineResult{
		TotalEvents:             log.TotalEvents,
		RegistrationEventsCount: regCount,
		ModificationEventsCount: modCount,
		PlaintextLogPath:        storage.GetPlaintextLogPath(p.outputDir),
		PlaintextLogHash:        plainDigest.Digest,
		EncryptedLogPath:        storage.GetEncryptedLogPath(p.outputDir),
		EncryptedLogHash:        encDigest.Digest,
		CryptoMetadataPath:      storage.GetCryptoMetadataPath(p.outputDir),
		DecryptedLogPath:        storage.GetDecryptedLogPath(p.outputDir),
		DecryptedLogHash:        decDigest.Digest,
		AuditReport:             auditReport,
	}, nil
}

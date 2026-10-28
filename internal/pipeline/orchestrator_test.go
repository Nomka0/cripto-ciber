package pipeline

import (
	"math/rand/v2"
	"os"
	"testing"

	"taller2-criptografia/internal/audit"
	"taller2-criptografia/internal/domain"
	"taller2-criptografia/internal/storage"
)

func TestPipelineOrchestrator_Run_Success(t *testing.T) {
	tempDir := t.TempDir()
	r := rand.New(rand.NewPCG(42, 1024))
	orch := NewPipelineOrchestrator(tempDir, r)

	const n = 30
	res, err := orch.Run(n)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.TotalEvents != n {
		t.Errorf("expected TotalEvents %d, got %d", n, res.TotalEvents)
	}
	if res.RegistrationEventsCount+res.ModificationEventsCount != n {
		t.Errorf("registration (%d) + modification (%d) != total (%d)",
			res.RegistrationEventsCount, res.ModificationEventsCount, n)
	}
	if res.RegistrationEventsCount == 0 {
		t.Errorf("expected at least one registration event")
	}

	// Hashes
	if len(res.PlaintextLogHash) != 64 {
		t.Errorf("invalid plaintext log hash length: %d", len(res.PlaintextLogHash))
	}
	if len(res.EncryptedLogHash) != 64 {
		t.Errorf("invalid encrypted log hash length: %d", len(res.EncryptedLogHash))
	}
	if len(res.DecryptedLogHash) != 64 {
		t.Errorf("invalid decrypted log hash length: %d", len(res.DecryptedLogHash))
	}
	if res.PlaintextLogHash != res.DecryptedLogHash {
		t.Errorf("plaintext hash (%s) does not match decrypted hash (%s)", res.PlaintextLogHash, res.DecryptedLogHash)
	}
	if res.PlaintextLogHash == res.EncryptedLogHash {
		t.Errorf("encrypted hash cannot match plaintext hash")
	}

	// Archivos en disco
	filesToCheck := []string{
		storage.GetPlaintextLogPath(tempDir),
		storage.GetPlaintextLogHashPath(tempDir),
		storage.GetEncryptedLogPath(tempDir),
		storage.GetCryptoMetadataPath(tempDir),
		storage.GetEncryptedLogHashPath(tempDir),
		storage.GetDecryptedLogPath(tempDir),
		storage.GetDecryptedLogHashPath(tempDir),
	}
	for _, f := range filesToCheck {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("expected artifact file to exist: %s (%v)", f, err)
		}
	}

	// Auditoría
	if res.AuditReport == nil {
		t.Fatal("expected non-nil AuditReport")
	}
	if !res.AuditReport.PreservationSuccess {
		t.Errorf("expected preservation success to be true")
	}
	if res.AuditReport.Verdict != audit.VerdictSuccess {
		t.Errorf("expected verdict %s, got %s", audit.VerdictSuccess, res.AuditReport.Verdict)
	}
	if res.AuditReport.RecordsVerification.TotalEvents != n {
		t.Errorf("expected audited records %d, got %d", n, res.AuditReport.RecordsVerification.TotalEvents)
	}
	if res.AuditReport.RecordsVerification.CorruptedEvents != 0 {
		t.Errorf("expected 0 corrupted records, got %d", res.AuditReport.RecordsVerification.CorruptedEvents)
	}
}

func TestPipelineOrchestrator_Steps_Sequence(t *testing.T) {
	tempDir := t.TempDir()
	r := rand.New(rand.NewPCG(99, 2048))
	orch := NewPipelineOrchestrator(tempDir, r)

	// Step 1: Generate & Consolidate (Pasos 2-4)
	log, reg, mod, err := orch.GenerateAndConsolidate(15)
	if err != nil {
		t.Fatalf("GenerateAndConsolidate failed: %v", err)
	}
	if log.TotalEvents != 15 || reg+mod != 15 {
		t.Errorf("unexpected counts: total=%d, reg=%d, mod=%d", log.TotalEvents, reg, mod)
	}

	// Step 2: Encrypt & Hash (Pasos 5-7)
	plainDigest, artifacts, encDigest, err := orch.EncryptAndHash()
	if err != nil {
		t.Fatalf("EncryptAndHash failed: %v", err)
	}
	if plainDigest.Digest == "" || encDigest.Digest == "" || artifacts == nil {
		t.Errorf("empty digest or artifacts returned")
	}

	// Step 3: Decrypt & Hash (Pasos 8-9)
	decBytes, decDigest, err := orch.DecryptAndHash()
	if err != nil {
		t.Fatalf("DecryptAndHash failed: %v", err)
	}
	if len(decBytes) == 0 || decDigest.Digest != plainDigest.Digest {
		t.Errorf("decrypted hash (%s) != plaintext hash (%s)", decDigest.Digest, plainDigest.Digest)
	}

	// Step 4: Audit (Paso 10)
	report, err := orch.Audit()
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}
	if !report.PreservationSuccess {
		t.Errorf("expected audit preservation success")
	}
}

func TestPipelineOrchestrator_InvalidVolume(t *testing.T) {
	orch := NewPipelineOrchestrator(t.TempDir(), nil)

	if _, _, _, err := orch.GenerateAndConsolidate(0); err != ErrInvalidVolume {
		t.Errorf("expected ErrInvalidVolume for 0, got %v", err)
	}
	if _, _, _, err := orch.GenerateAndConsolidate(-5); err != ErrInvalidVolume {
		t.Errorf("expected ErrInvalidVolume for -5, got %v", err)
	}
	if _, err := orch.Run(0); err != ErrInvalidVolume {
		t.Errorf("expected ErrInvalidVolume on Run(0), got %v", err)
	}
}

func TestPipelineOrchestrator_MissingDependencies(t *testing.T) {
	tempDir := t.TempDir()
	orch := NewPipelineOrchestrator(tempDir, nil)

	// Encrypt without prior generation
	if _, _, _, err := orch.EncryptAndHash(); err != ErrPlaintextLogNotFound {
		t.Errorf("expected ErrPlaintextLogNotFound, got %v", err)
	}

	// Decrypt without prior encryption
	if _, _, err := orch.DecryptAndHash(); err != ErrEncryptedLogNotFound {
		t.Errorf("expected ErrEncryptedLogNotFound, got %v", err)
	}

	// Audit without prior decryption
	if _, err := orch.Audit(); err != ErrPlaintextLogNotFound {
		t.Errorf("expected ErrPlaintextLogNotFound, got %v", err)
	}
}

func TestPipelineOrchestrator_TamperingDetection(t *testing.T) {
	tempDir := t.TempDir()
	orch := NewPipelineOrchestrator(tempDir, nil)

	if _, _, _, err := orch.GenerateAndConsolidate(10); err != nil {
		t.Fatalf("generation failed: %v", err)
	}
	if _, _, _, err := orch.EncryptAndHash(); err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Alterar 1 byte del archivo cifrado
	encPath := storage.GetEncryptedLogPath(tempDir)
	ciphertext, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("failed to read ciphertext: %v", err)
	}
	ciphertext[0] ^= 0xFF
	if err := os.WriteFile(encPath, ciphertext, 0600); err != nil {
		t.Fatalf("failed to write corrupted ciphertext: %v", err)
	}

	// DecryptAndHash debe fallar por autenticación
	_, _, err = orch.DecryptAndHash()
	if err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext")
	}

	// No debe haberse escrito el archivo descifrado
	decPath := storage.GetDecryptedLogPath(tempDir)
	if _, err := os.Stat(decPath); !os.IsNotExist(err) {
		t.Errorf("decrypted log file must not exist after failed authentication")
	}
}

func TestPipelineOrchestrator_ForensicTamperingDetection(t *testing.T) {
	tempDir := t.TempDir()
	orch := NewPipelineOrchestrator(tempDir, nil)

	if _, err := orch.Run(10); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	// Modificar el archivo descifrado directamente en disco
	decPath := storage.GetDecryptedLogPath(tempDir)
	decLog, err := storage.LoadConsolidatedLogFromFile(decPath)
	if err != nil {
		t.Fatalf("failed to load decrypted log: %v", err)
	}

	// Adulterar la primera nota
	switch e := decLog.Events[0].(type) {
	case *domain.GradeRegistrationEvent:
		e.Payload.Grade = 0.0
	case *domain.GradeModificationEvent:
		e.Payload.NewGrade = 0.0
	}
	if err := storage.SaveConsolidatedLogToFile(decPath, decLog); err != nil {
		t.Fatalf("failed to overwrite decrypted log: %v", err)
	}

	// Re-ejecutar auditoría
	report, err := orch.Audit()
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}

	if report.PreservationSuccess {
		t.Errorf("expected preservation success to be false on tampered log")
	}
	if report.Verdict != audit.VerdictCorrupted {
		t.Errorf("expected verdict %s, got %s", audit.VerdictCorrupted, report.Verdict)
	}
	if report.RecordsVerification.CorruptedEvents != 1 {
		t.Errorf("expected 1 corrupted record, got %d", report.RecordsVerification.CorruptedEvents)
	}
}

func TestPipelineOrchestrator_DefaultOutputDir(t *testing.T) {
	orch := NewPipelineOrchestrator("", nil)
	if orch.OutputDir() != storage.DefaultOutputDir {
		t.Errorf("expected default output dir %s, got %s", storage.DefaultOutputDir, orch.OutputDir())
	}
}

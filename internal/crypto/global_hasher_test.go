package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestComputeFileSHA256_NISTVectors(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		content  []byte
		expected string
	}{
		{
			name:     "NIST Vector 1: Empty file",
			content:  []byte(""),
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "NIST Vector 2: Single line 'abc'",
			content:  []byte("abc"),
			expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			name:     "NIST Vector 3: 448-bit string",
			content:  []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
			expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, strings.ReplaceAll(tc.name, " ", "_")+".dat")
			if err := os.WriteFile(filePath, tc.content, 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			digest, err := ComputeFileSHA256(filePath)
			if err != nil {
				t.Fatalf("ComputeFileSHA256 returned unexpected error: %v", err)
			}

			if digest != tc.expected {
				t.Errorf("digest mismatch:\nexpected: %s\ngot:      %s", tc.expected, digest)
			}
		})
	}
}

func TestComputeFileSHA256_SyntheticLargeFileStreaming(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "large_synthetic_log.dat")

	// Crear archivo sintético de 2 Megabytes (2 * 1024 * 1024 bytes)
	fileSize := 2 * 1024 * 1024
	pattern := []byte("ACADEMIC_FORENSIC_LOG_ENTRY_STREAMING_TEST_CHUNK_")
	data := make([]byte, fileSize)
	for i := 0; i < fileSize; i++ {
		data[i] = pattern[i%len(pattern)]
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("failed to create synthetic large file: %v", err)
	}

	// Computar digest esperado en memoria usando ComputeSHA256 nativo
	expectedDigest := ComputeSHA256(data)

	// Computar vía streaming desde disco usando ComputeFileSHA256
	streamDigest, err := ComputeFileSHA256(filePath)
	if err != nil {
		t.Fatalf("streaming calculation failed: %v", err)
	}

	if streamDigest != expectedDigest {
		t.Errorf("streaming digest does not match in-memory hash:\nexpected: %s\ngot:      %s",
			expectedDigest, streamDigest)
	}
}

func TestCoreutilsFormatAndParsing(t *testing.T) {
	digest := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	filename := "academic_log.json"

	// 1. Formateo estándar BSD/GNU coreutils
	formatted := FormatCoreutilsDigest(digest, filename)
	expectedFormat := digest + "  " + filename + "\n"
	if formatted != expectedFormat {
		t.Fatalf("unexpected formatted line:\nexpected: %q\ngot:      %q", expectedFormat, formatted)
	}

	// 2. Parseo exitoso modo texto estándar (dos espacios)
	parsedDigest, parsedFile, err := ParseCoreutilsDigest(formatted)
	if err != nil {
		t.Fatalf("failed to parse standard coreutils digest: %v", err)
	}
	if parsedDigest != digest {
		t.Errorf("parsed digest mismatch: expected %s, got %s", digest, parsedDigest)
	}
	if parsedFile != filename {
		t.Errorf("parsed filename mismatch: expected %s, got %s", filename, parsedFile)
	}

	// 3. Parseo modo binario (un espacio y asterisco)
	binaryLine := fmt.Sprintf("%s *%s\n", digest, filename)
	bDigest, bFile, err := ParseCoreutilsDigest(binaryLine)
	if err != nil {
		t.Fatalf("failed to parse binary mode coreutils line: %v", err)
	}
	if bDigest != digest || bFile != filename {
		t.Errorf("binary mode parsing mismatch: got digest=%s, file=%s", bDigest, bFile)
	}

	// 4. Parseo con comentarios previos
	commentedContent := fmt.Sprintf("# Hash de verificación forense\n%s  %s\n", digest, filename)
	cDigest, cFile, err := ParseCoreutilsDigest(commentedContent)
	if err != nil {
		t.Fatalf("failed to parse commented digest file: %v", err)
	}
	if cDigest != digest || cFile != filename {
		t.Errorf("comment parsing mismatch: got digest=%s, file=%s", cDigest, cFile)
	}

	// 5. Casos de error en parseo
	invalidCases := []struct {
		name    string
		content string
		wantErr error
	}{
		{"Empty content", "", ErrInvalidDigestFormat},
		{"Whitespace only", "   \n\t  ", ErrInvalidDigestFormat},
		{"Single word without filename", digest, ErrInvalidDigestFormat},
		{"Short hash length (63 chars)", digest[:63] + "  file.json", ErrInvalidDigestLength},
		{"Long hash length (65 chars)", digest + "a  file.json", ErrInvalidDigestLength},
		{"Non-hex characters in hash", strings.Repeat("z", 64) + "  file.json", ErrInvalidDigestFormat},
	}

	for _, ic := range invalidCases {
		t.Run(ic.name, func(t *testing.T) {
			_, _, err := ParseCoreutilsDigest(ic.content)
			if err == nil {
				t.Fatalf("expected error for case %q, but got nil", ic.name)
			}
			if ic.wantErr != nil && !errors.Is(err, ic.wantErr) {
				t.Errorf("expected error %v, got %v", ic.wantErr, err)
			}
		})
	}
}

func TestGlobalHasher_WorkflowSteps5_7_9(t *testing.T) {
	tempDir := t.TempDir()
	hasher := NewGlobalHasher()

	// -------------------------------------------------------------
	// PASO 5: Hash del log original en claro (academic_log.json)
	// -------------------------------------------------------------
	plaintextLogPath := filepath.Join(tempDir, "academic_log.json")
	sampleJSON := []byte(`[
  {"event_id": "EVT-001", "type": "REGISTRO_NOTA", "grade": 4.5},
  {"event_id": "EVT-002", "type": "MODIFICACION_NOTA", "previous_grade": 4.5, "new_grade": 4.8}
]`)
	if err := os.WriteFile(plaintextLogPath, sampleJSON, 0644); err != nil {
		t.Fatalf("failed to write plaintext log: %v", err)
	}

	resStep5, err := hasher.HashPlaintextLog(plaintextLogPath)
	if err != nil {
		t.Fatalf("Paso 5 HashPlaintextLog failed: %v", err)
	}

	if len(resStep5.Digest) != 64 {
		t.Errorf("expected 64 characters hex digest, got %d", len(resStep5.Digest))
	}
	expectedWitnessStep5 := plaintextLogPath + ".sha256"
	if resStep5.DigestFilePath != expectedWitnessStep5 {
		t.Errorf("expected digest path %s, got %s", expectedWitnessStep5, resStep5.DigestFilePath)
	}

	// Verificar que el archivo .sha256 físico fue creado y contiene formato coreutils
	witnessBytes, err := os.ReadFile(expectedWitnessStep5)
	if err != nil {
		t.Fatalf("failed to read created witness file for step 5: %v", err)
	}
	parsedWitnessHash, parsedWitnessFile, err := ParseCoreutilsDigest(string(witnessBytes))
	if err != nil {
		t.Fatalf("failed to parse step 5 witness: %v", err)
	}
	if parsedWitnessHash != resStep5.Digest {
		t.Errorf("witness hash mismatch: expected %s, got %s", resStep5.Digest, parsedWitnessHash)
	}
	if parsedWitnessFile != "academic_log.json" {
		t.Errorf("witness filename mismatch: expected 'academic_log.json', got %s", parsedWitnessFile)
	}

	// -------------------------------------------------------------
	// PASO 7: Hash del log cifrado (academic_log.enc)
	// -------------------------------------------------------------
	encryptedPath := filepath.Join(tempDir, "academic_log.enc")
	ciphertextPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03}
	if err := os.WriteFile(encryptedPath, ciphertextPayload, 0644); err != nil {
		t.Fatalf("failed to write encrypted artifact: %v", err)
	}

	resStep7, err := hasher.HashEncryptedLog(encryptedPath)
	if err != nil {
		t.Fatalf("Paso 7 HashEncryptedLog failed: %v", err)
	}

	if resStep7.Digest == resStep5.Digest {
		t.Errorf("encrypted digest must be different from plaintext digest")
	}
	expectedWitnessStep7 := encryptedPath + ".sha256"
	if _, err := os.Stat(expectedWitnessStep7); err != nil {
		t.Fatalf("encrypted witness file %s was not created on disk", expectedWitnessStep7)
	}

	// -------------------------------------------------------------
	// PASO 9: Hash del log recuperado tras descifrado (academic_log_decrypted.json)
	// -------------------------------------------------------------
	decryptedPath := filepath.Join(tempDir, "academic_log_decrypted.json")
	// En un descifrado exitoso, los bytes recuperados son idénticos a los originales
	if err := os.WriteFile(decryptedPath, sampleJSON, 0644); err != nil {
		t.Fatalf("failed to write decrypted log: %v", err)
	}

	// 9a. Calcular digest en memoria para auditoría sin persistencia obligatoria
	resStep9Mem, err := hasher.HashDecryptedLog(decryptedPath, false)
	if err != nil {
		t.Fatalf("Paso 9 HashDecryptedLog (memory) failed: %v", err)
	}
	if resStep9Mem.DigestFilePath != "" {
		t.Errorf("expected empty DigestFilePath when persist=false, got %s", resStep9Mem.DigestFilePath)
	}

	// Comparar contra el hash del Paso 5
	if !CompareDigests(resStep9Mem.Digest, resStep5.Digest) {
		t.Fatalf("forensic integrity check failed: decrypted digest (%s) != original plaintext digest (%s)",
			resStep9Mem.Digest, resStep5.Digest)
	}

	// 9b. Calcular con persistencia opcional
	resStep9Persisted, err := hasher.HashDecryptedLog(decryptedPath, true)
	if err != nil {
		t.Fatalf("Paso 9 HashDecryptedLog (persisted) failed: %v", err)
	}
	if resStep9Persisted.Digest != resStep5.Digest {
		t.Errorf("persisted step 9 digest mismatch")
	}
	if _, err := os.Stat(decryptedPath + ".sha256"); err != nil {
		t.Errorf("step 9 witness file was not created: %v", err)
	}
}

func TestVerifyFileAgainstDigestFile_ForensicTamperingDetection(t *testing.T) {
	tempDir := t.TempDir()
	hasher := NewGlobalHasher()

	filePath := filepath.Join(tempDir, "integrity_target.json")
	originalContent := []byte(`{"student_uid":"USR-STU-001","grade":5.0}`)
	if err := os.WriteFile(filePath, originalContent, 0644); err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}

	result, err := hasher.HashAndPersist(filePath)
	if err != nil {
		t.Fatalf("failed to hash and persist: %v", err)
	}

	// 1. Archivo íntegro: debe validar true
	match, computed, err := hasher.VerifyFileAgainstDigestFile(filePath, result.DigestFilePath)
	if err != nil {
		t.Fatalf("verification error on intact file: %v", err)
	}
	if !match {
		t.Errorf("expected intact file to match witness")
	}
	if computed != result.Digest {
		t.Errorf("computed digest mismatch: %s vs %s", computed, result.Digest)
	}

	// 2. Modificación de un solo bit / caracter (adulteración de nota de 5.0 a 1.0)
	tamperedContent := bytes.Replace(originalContent, []byte("5.0"), []byte("1.0"), 1)
	if err := os.WriteFile(filePath, tamperedContent, 0644); err != nil {
		t.Fatalf("failed to tamper file: %v", err)
	}

	matchTampered, tamperedComputed, err := hasher.VerifyFileAgainstDigestFile(filePath, result.DigestFilePath)
	if err != nil {
		t.Fatalf("verification error on tampered file: %v", err)
	}
	if matchTampered {
		t.Errorf("CRITICAL SECURITY FAILURE: tampered file was falsely validated as intact!")
	}
	if tamperedComputed == result.Digest {
		t.Errorf("tampered digest cannot match original digest")
	}
}

func TestGlobalHasher_ErrorCases(t *testing.T) {
	tempDir := t.TempDir()
	hasher := NewGlobalHasher()

	// 1. Ruta vacía
	if _, err := hasher.HashFile(""); !errors.Is(err, ErrEmptyFilePath) {
		t.Errorf("expected ErrEmptyFilePath, got %v", err)
	}
	if _, err := hasher.HashAndPersist("   "); !errors.Is(err, ErrEmptyFilePath) {
		t.Errorf("expected ErrEmptyFilePath for spaces, got %v", err)
	}

	// 2. Archivo inexistente
	if _, err := hasher.HashFile(filepath.Join(tempDir, "non_existent.txt")); err == nil {
		t.Errorf("expected error for non-existent file, got nil")
	}

	// 3. Directorio en vez de archivo regular
	dirPath := filepath.Join(tempDir, "sub_directory")
	if err := os.Mkdir(dirPath, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if _, err := hasher.HashFile(dirPath); !errors.Is(err, ErrNotRegularFile) {
		t.Errorf("expected ErrNotRegularFile for directory, got %v", err)
	}

	// 4. Verificación con archivo testigo inexistente
	validFile := filepath.Join(tempDir, "file.txt")
	_ = os.WriteFile(validFile, []byte("hello"), 0644)
	if _, _, err := hasher.VerifyFileAgainstDigestFile(validFile, "missing.sha256"); err == nil {
		t.Errorf("expected error with missing witness file, got nil")
	}

	// 5. Verificación con archivo testigo corrupto
	corruptWitness := filepath.Join(tempDir, "corrupt.sha256")
	_ = os.WriteFile(corruptWitness, []byte("not_a_valid_hash  file.txt"), 0644)
	if _, _, err := hasher.VerifyFileAgainstDigestFile(validFile, corruptWitness); err == nil {
		t.Errorf("expected error with corrupt witness, got nil")
	}
}

func TestCompareDigests_ConstantTime(t *testing.T) {
	h1 := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	h2 := "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD" // Upper case
	h3 := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae" // 1 char diff
	h4 := "ba7816bf"                                                           // different length

	if !CompareDigests(h1, h2) {
		t.Errorf("expected case-insensitive match for digests")
	}

	if CompareDigests(h1, h3) {
		t.Errorf("expected mismatch for differing digests")
	}

	if CompareDigests(h1, h4) {
		t.Errorf("expected mismatch for different lengths")
	}
}

func TestGlobalHasher_ConcurrentExecution(t *testing.T) {
	tempDir := t.TempDir()
	hasher := NewGlobalHasher()

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		workerID := i
		go func() {
			defer wg.Done()
			fPath := filepath.Join(tempDir, fmt.Sprintf("concurrent_%d.log", workerID))
			content := fmt.Sprintf("Event content for worker %d with unique data", workerID)
			if err := os.WriteFile(fPath, []byte(content), 0644); err != nil {
				t.Errorf("worker %d failed to write file: %v", workerID, err)
				return
			}

			res, err := hasher.HashAndPersist(fPath)
			if err != nil {
				t.Errorf("worker %d HashAndPersist failed: %v", workerID, err)
				return
			}

			ok, _, err := hasher.VerifyFileAgainstDigestFile(fPath, res.DigestFilePath)
			if err != nil || !ok {
				t.Errorf("worker %d verification failed: ok=%v, err=%v", workerID, ok, err)
			}
		}()
	}

	wg.Wait()
}

package storage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"taller2-criptografia/internal/domain"
)

func TestLogSchema(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	log := NewConsolidatedAcademicLog("LOG-20261020-001", "AUDIT_SIMULATION")
	log.Metadata.CreatedAt = now

	// 1. Crear 5 eventos (3 registros y 2 modificaciones) con sus respectivos hashes de payload
	reg1, err := domain.NewGradeRegistrationEvent("EVT-REG-00001", domain.GradeRegistrationPayload{
		StudentUID:   "STU-001",
		SubjectUID:   "SUB-750001C-CRIPTO",
		EvaluatorUID: "DOC-001",
		Grade:        4.5,
		Evaluation:   "Taller 1",
		Timestamp:    now.Add(-40 * time.Minute),
	})
	if err != nil {
		t.Fatalf("unexpected error creating reg1: %v", err)
	}
	reg1.PayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	reg2, err := domain.NewGradeRegistrationEvent("EVT-REG-00002", domain.GradeRegistrationPayload{
		StudentUID:   "STU-002",
		SubjectUID:   "SUB-750002C-BD",
		EvaluatorUID: "DOC-002",
		Grade:        3.8,
		Evaluation:   "Parcial 1",
		Timestamp:    now.Add(-30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("unexpected error creating reg2: %v", err)
	}
	reg2.PayloadHash = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"

	mod1, err := domain.NewGradeModificationEvent("EVT-MOD-00003", domain.GradeModificationPayload{
		StudentUID:    "STU-001",
		SubjectUID:    "SUB-750001C-CRIPTO",
		ModifierUID:   "DOC-001",
		PreviousGrade: 4.5,
		NewGrade:      4.8,
		Reason:        "Revisión de reclamo presencial punto 2",
		Evaluation:    "Taller 1",
		Timestamp:     now.Add(-20 * time.Minute),
	})
	if err != nil {
		t.Fatalf("unexpected error creating mod1: %v", err)
	}
	mod1.PayloadHash = "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"

	reg3, err := domain.NewGradeRegistrationEvent("EVT-REG-00004", domain.GradeRegistrationPayload{
		StudentUID:   "STU-003",
		SubjectUID:   "SUB-750003C-ED",
		EvaluatorUID: "DOC-003",
		Grade:        2.9,
		Evaluation:   "Quiz 1",
		Timestamp:    now.Add(-10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("unexpected error creating reg3: %v", err)
	}
	reg3.PayloadHash = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"

	mod2, err := domain.NewGradeModificationEvent("EVT-MOD-00005", domain.GradeModificationPayload{
		StudentUID:    "STU-003",
		SubjectUID:    "SUB-750003C-ED",
		ModifierUID:   "DOC-003",
		PreviousGrade: 2.9,
		NewGrade:      3.5,
		Reason:        "Sustentación oral de código aprobada",
		Evaluation:    "Quiz 1",
		Timestamp:     now,
	})
	if err != nil {
		t.Fatalf("unexpected error creating mod2: %v", err)
	}
	mod2.PayloadHash = "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d"

	// 2. Agregar los 5 eventos polimórficos
	log.AddEvent(reg1)
	log.AddEvent(reg2)
	log.AddEvent(mod1)
	log.AddEvent(reg3)
	log.AddEvent(mod2)

	// 3. Validar consistencia previa a serialización
	if err := log.Validate(); err != nil {
		t.Fatalf("log validation failed: %v", err)
	}

	// 4. Serializar a JSON
	jsonBytes, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal log to JSON: %v", err)
	}

	// 5. Validar estructura JSON raíz
	var rawRoot map[string]json.RawMessage
	if err := json.Unmarshal(jsonBytes, &rawRoot); err != nil {
		t.Fatalf("failed to parse JSON into raw map: %v", err)
	}

	if len(rawRoot) != 2 {
		t.Fatalf("expected exactly 2 root keys (metadata, events), got %d", len(rawRoot))
	}
	if _, ok := rawRoot["metadata"]; !ok {
		t.Fatal("missing 'metadata' key in JSON root")
	}
	if _, ok := rawRoot["events"]; !ok {
		t.Fatal("missing 'events' key in JSON root")
	}

	// Validar contenido de metadata
	var meta LogMetadata
	if err := json.Unmarshal(rawRoot["metadata"], &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if meta.LogID != "LOG-20261020-001" {
		t.Errorf("expected LogID 'LOG-20261020-001', got %q", meta.LogID)
	}
	if meta.SchemaVersion != "1.0.0" {
		t.Errorf("expected SchemaVersion '1.0.0', got %q", meta.SchemaVersion)
	}
	if meta.TotalEvents != 5 {
		t.Errorf("expected TotalEvents 5, got %d", meta.TotalEvents)
	}
	if meta.Environment != "AUDIT_SIMULATION" {
		t.Errorf("expected Environment 'AUDIT_SIMULATION', got %q", meta.Environment)
	}

	// Validar array de eventos en JSON crudo
	var rawEvents []map[string]any
	if err := json.Unmarshal(rawRoot["events"], &rawEvents); err != nil {
		t.Fatalf("failed to unmarshal raw events array: %v", err)
	}
	if len(rawEvents) != 5 {
		t.Fatalf("expected 5 raw events, got %d", len(rawEvents))
	}

	for i, evt := range rawEvents {
		if _, ok := evt["event_id"]; !ok {
			t.Errorf("event at index %d missing 'event_id'", i)
		}
		if _, ok := evt["event_type"]; !ok {
			t.Errorf("event at index %d missing 'event_type'", i)
		}
		if _, ok := evt["payload"]; !ok {
			t.Errorf("event at index %d missing 'payload'", i)
		}
		if _, ok := evt["payload_hash"]; !ok {
			t.Errorf("event at index %d missing 'payload_hash'", i)
		}
	}

	// 6. Deserializar polimórficamente de vuelta a ConsolidatedAcademicLog
	var restoredLog ConsolidatedAcademicLog
	if err := json.Unmarshal(jsonBytes, &restoredLog); err != nil {
		t.Fatalf("failed to unmarshal JSON into ConsolidatedAcademicLog: %v", err)
	}

	if err := restoredLog.Validate(); err != nil {
		t.Fatalf("restored log validation failed: %v", err)
	}

	if restoredLog.Metadata.TotalEvents != 5 || len(restoredLog.Events) != 5 {
		t.Fatalf("expected 5 events in restored log, got metadata=%d, slice=%d",
			restoredLog.Metadata.TotalEvents, len(restoredLog.Events))
	}

	// Verificar tipos concretos y preservación de campos específicos
	firstReg, ok := restoredLog.Events[0].(*domain.GradeRegistrationEvent)
	if !ok {
		t.Fatalf("expected index 0 to be *domain.GradeRegistrationEvent, got %T", restoredLog.Events[0])
	}
	if firstReg.Payload.Grade != 4.5 || firstReg.PayloadHash != reg1.PayloadHash {
		t.Errorf("data mismatch in registration event: grade=%f, hash=%s",
			firstReg.Payload.Grade, firstReg.PayloadHash)
	}

	firstMod, ok := restoredLog.Events[2].(*domain.GradeModificationEvent)
	if !ok {
		t.Fatalf("expected index 2 to be *domain.GradeModificationEvent, got %T", restoredLog.Events[2])
	}
	if firstMod.Payload.PreviousGrade != 4.5 || firstMod.Payload.NewGrade != 4.8 || !strings.Contains(firstMod.Payload.Reason, "reclamo") {
		t.Errorf("data mismatch in modification event: prev=%f, new=%f, reason=%s",
			firstMod.Payload.PreviousGrade, firstMod.Payload.NewGrade, firstMod.Payload.Reason)
	}
}

func TestLogValidationErrors(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name        string
		modify      func(l *ConsolidatedAcademicLog)
		expectedErr error
	}{
		{
			name: "empty log_id",
			modify: func(l *ConsolidatedAcademicLog) {
				l.Metadata.LogID = ""
			},
			expectedErr: ErrEmptyLogID,
		},
		{
			name: "empty schema_version",
			modify: func(l *ConsolidatedAcademicLog) {
				l.Metadata.SchemaVersion = ""
			},
			expectedErr: ErrEmptySchemaVersion,
		},
		{
			name: "zero created_at",
			modify: func(l *ConsolidatedAcademicLog) {
				l.Metadata.CreatedAt = time.Time{}
			},
			expectedErr: ErrZeroCreatedAt,
		},
		{
			name: "empty environment",
			modify: func(l *ConsolidatedAcademicLog) {
				l.Metadata.Environment = ""
			},
			expectedErr: ErrEmptyEnvironment,
		},
		{
			name: "total_events mismatch",
			modify: func(l *ConsolidatedAcademicLog) {
				l.Metadata.TotalEvents = 99
			},
			expectedErr: ErrEventCountMismatch,
		},
		{
			name: "nil event in slice",
			modify: func(l *ConsolidatedAcademicLog) {
				l.Events = append(l.Events, nil)
				l.Metadata.TotalEvents = len(l.Events)
			},
			expectedErr: ErrNilEvent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewConsolidatedAcademicLog("LOG-001", "AUDIT_SIMULATION")
			l.Metadata.CreatedAt = now
			tt.modify(l)

			err := l.Validate()
			if err == nil {
				t.Fatalf("expected error containing %v, got nil", tt.expectedErr)
			}
			if !strings.Contains(err.Error(), tt.expectedErr.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

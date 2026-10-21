package crypto

import (
	"errors"
	"strings"
	"testing"
	"time"

	"taller2-criptografia/internal/domain"
)

func TestComputeSHA256Vectors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "NIST Vector 1: Empty string",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "NIST Vector 2: String 'abc'",
			input:    "abc",
			expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			name:     "NIST Vector 3: 448-bit string",
			input:    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeSHA256([]byte(tc.input))

			if len(got) != 64 {
				t.Fatalf("expected 64 characters hex digest, got length %d", len(got))
			}

			if got != strings.ToLower(got) {
				t.Errorf("expected lowercase hex, got %s", got)
			}

			if got != tc.expected {
				t.Errorf("digest mismatch:\nexpected: %s\ngot:      %s", tc.expected, got)
			}

			// Verify stream calculation matches
			streamGot, err := ComputeStreamSHA256(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("unexpected stream error: %v", err)
			}
			if streamGot != tc.expected {
				t.Errorf("stream digest mismatch:\nexpected: %s\ngot:      %s", tc.expected, streamGot)
			}
		})
	}
}

func TestComputeStreamSHA256_NilReader(t *testing.T) {
	_, err := ComputeStreamSHA256(nil)
	if !errors.Is(err, ErrNilReader) {
		t.Errorf("expected ErrNilReader, got %v", err)
	}
}

func TestComputePayloadHash(t *testing.T) {
	fixedTime := time.Date(2026, time.May, 1, 14, 0, 0, 0, time.UTC)
	payload := domain.GradeRegistrationPayload{
		StudentUID:   "STD-HASH-01",
		SubjectUID:   "SUBJ-HASH-01",
		EvaluatorUID: "PROF-01",
		Grade:        4.8,
		Evaluation:   "Taller Criptografia",
		Timestamp:    fixedTime,
	}

	eventWithoutHash := domain.GradeRegistrationEvent{
		EventID:     "EVT-01",
		EventType:   domain.EventTypeRegistration,
		Payload:     payload,
		PayloadHash: "",
	}

	hashFromEvent, err := ComputePayloadHash(eventWithoutHash)
	if err != nil {
		t.Fatalf("ComputePayloadHash failed for event: %v", err)
	}

	if len(hashFromEvent) != 64 {
		t.Fatalf("expected 64 characters hex, got %d", len(hashFromEvent))
	}

	eventWithHash := eventWithoutHash
	eventWithHash.PayloadHash = hashFromEvent

	hashFromPopulatedEvent, err := ComputePayloadHash(eventWithHash)
	if err != nil {
		t.Fatalf("ComputePayloadHash failed for populated event: %v", err)
	}

	if hashFromEvent != hashFromPopulatedEvent {
		t.Errorf("hashes differ between unhashed and hashed event: %s vs %s", hashFromEvent, hashFromPopulatedEvent)
	}

	hashFromDirectPayload, err := ComputePayloadHash(payload)
	if err != nil {
		t.Fatalf("ComputePayloadHash failed for direct payload: %v", err)
	}

	if hashFromEvent != hashFromDirectPayload {
		t.Errorf("hash from event container differs from direct payload: %s vs %s", hashFromEvent, hashFromDirectPayload)
	}
}

package crypto

import (
	"bytes"
	"encoding/json"
	"errors"

	"taller2-criptografia/internal/domain"
)

var (
	ErrNilPayload               = errors.New("payload cannot be nil")
	ErrUnsupportedPayloadType   = errors.New("unsupported payload or event type")
	ErrCircularMetadataDetected = errors.New("circular metadata detected in extracted payload")
)

// ExtractRegistrationPayload extrae el struct GradeRegistrationPayload puro desde un evento o payload.
func ExtractRegistrationPayload(input interface{}) (*domain.GradeRegistrationPayload, error) {
	if input == nil {
		return nil, ErrNilPayload
	}

	switch v := input.(type) {
	case *domain.GradeRegistrationEvent:
		if v == nil {
			return nil, ErrNilPayload
		}
		return &v.Payload, nil
	case domain.GradeRegistrationEvent:
		return &v.Payload, nil
	case *domain.GradeRegistrationPayload:
		if v == nil {
			return nil, ErrNilPayload
		}
		return v, nil
	case domain.GradeRegistrationPayload:
		return &v, nil
	default:
		return nil, ErrUnsupportedPayloadType
	}
}

// ExtractModificationPayload extrae el struct GradeModificationPayload puro desde un evento o payload.
func ExtractModificationPayload(input interface{}) (*domain.GradeModificationPayload, error) {
	if input == nil {
		return nil, ErrNilPayload
	}

	switch v := input.(type) {
	case *domain.GradeModificationEvent:
		if v == nil {
			return nil, ErrNilPayload
		}
		return &v.Payload, nil
	case domain.GradeModificationEvent:
		return &v.Payload, nil
	case *domain.GradeModificationPayload:
		if v == nil {
			return nil, ErrNilPayload
		}
		return v, nil
	case domain.GradeModificationPayload:
		return &v, nil
	default:
		return nil, ErrUnsupportedPayloadType
	}
}

// ExtractPayload extrae de forma polimórfica el struct de payload puro desde cualquier evento académico o payload soportado.
func ExtractPayload(input interface{}) (interface{}, error) {
	if input == nil {
		return nil, ErrNilPayload
	}

	switch v := input.(type) {
	case *domain.GradeRegistrationEvent, domain.GradeRegistrationEvent,
		*domain.GradeRegistrationPayload, domain.GradeRegistrationPayload:
		return ExtractRegistrationPayload(v)
	case *domain.GradeModificationEvent, domain.GradeModificationEvent,
		*domain.GradeModificationPayload, domain.GradeModificationPayload:
		return ExtractModificationPayload(v)
	default:
		return nil, ErrUnsupportedPayloadType
	}
}

// Canonicalize serializa una estructura de payload a JSON canónico determinista.
// Valida estructuralmente que no contenga referencias circulares a payload_hash.
func Canonicalize(payload interface{}) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	if bytes.Contains(raw, []byte(`"payload_hash":`)) {
		return nil, ErrCircularMetadataDetected
	}

	return raw, nil
}

// ExtractRegistrationPayloadBytes extrae y serializa canónicamente el payload de registro de notas.
func ExtractRegistrationPayloadBytes(input interface{}) ([]byte, error) {
	p, err := ExtractRegistrationPayload(input)
	if err != nil {
		return nil, err
	}
	return Canonicalize(p)
}

// ExtractModificationPayloadBytes extrae y serializa canónicamente el payload de modificación de notas.
func ExtractModificationPayloadBytes(input interface{}) ([]byte, error) {
	p, err := ExtractModificationPayload(input)
	if err != nil {
		return nil, err
	}
	return Canonicalize(p)
}

// ExtractPayloadBytes extrae la representación canónica en bytes del payload puro de un evento o payload.
// Desacopla estructuralmente los datos de negocio excluyendo el identificador de evento y el campo payload_hash.
func ExtractPayloadBytes(input interface{}) ([]byte, error) {
	payload, err := ExtractPayload(input)
	if err != nil {
		return nil, err
	}
	return Canonicalize(payload)
}

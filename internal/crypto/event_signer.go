package crypto

import (
	"errors"
	"fmt"
	"log"

	"taller2-criptografia/internal/domain"
)

var (
	ErrNilEvent             = errors.New("event cannot be nil")
	ErrUnsupportedEventType = errors.New("unsupported event type for signing")
)

// EventEnricher define el contrato para enriquecer eventos con su digest criptográfico.
type EventEnricher interface {
	EnrichWithHash(event domain.GenericEvent) error
}

// DefaultEventEnricher es la implementación predeterminada de EventEnricher.
type DefaultEventEnricher struct{}

// NewEventEnricher crea una nueva instancia de EventEnricher.
func NewEventEnricher() EventEnricher {
	return &DefaultEventEnricher{}
}

// EnrichWithHash delega el enriquecimiento a SignEventPayload.
func (e *DefaultEventEnricher) EnrichWithHash(event domain.GenericEvent) error {
	return SignEventPayload(event)
}

func isNilEvent(event domain.GenericEvent) bool {
	if event == nil {
		return true
	}
	switch e := event.(type) {
	case *domain.GradeRegistrationEvent:
		return e == nil
	case *domain.GradeModificationEvent:
		return e == nil
	}
	return false
}

// SignEventPayload toma el payload del evento, calcula su digest SHA-256 e inscribe
// el resultado en el campo PayloadHash de forma controlada.
func SignEventPayload(event domain.GenericEvent) error {
	if isNilEvent(event) {
		return ErrNilEvent
	}

	digest, err := ComputePayloadHash(event)
	if err != nil {
		return fmt.Errorf("failed to compute payload hash: %w", err)
	}

	preExisting := event.GetPayloadHash()
	if preExisting != "" && preExisting != digest {
		log.Printf("warning: overwriting pre-existing payload_hash for event %s (was %s, now %s)",
			event.GetEventID(), preExisting, digest)
	}

	switch e := event.(type) {
	case *domain.GradeRegistrationEvent:
		e.PayloadHash = digest
		return nil
	case *domain.GradeModificationEvent:
		e.PayloadHash = digest
		return nil
	default:
		if setter, ok := event.(interface{ SetPayloadHash(string) }); ok {
			setter.SetPayloadHash(digest)
			return nil
		}
		return fmt.Errorf("%w: %T", ErrUnsupportedEventType, event)
	}
}

// VerifyEventPayloadHash recalcula el hash SHA-256 del payload y lo compara con el campo incrustado.
// Retorna true si y solo si el hash coincide; retorna false si el campo está vacío o difiere.
func VerifyEventPayloadHash(event domain.GenericEvent) (bool, error) {
	if isNilEvent(event) {
		return false, ErrNilEvent
	}

	embeddedHash := event.GetPayloadHash()
	if embeddedHash == "" {
		return false, nil
	}

	computedHash, err := ComputePayloadHash(event)
	if err != nil {
		return false, fmt.Errorf("failed to recompute payload hash: %w", err)
	}

	return computedHash == embeddedHash, nil
}

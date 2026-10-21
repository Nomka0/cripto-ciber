package domain

import (
	"errors"
	"testing"
	"time"
)

func TestBaseModels(t *testing.T) {
	t.Run("BaseActor validation", func(t *testing.T) {
		validActor := BaseActor{
			ActorUID: "USR-9b2f-48e1",
			Role:     RoleTeacher,
		}
		if err := validActor.Validate(); err != nil {
			t.Fatalf("expected valid actor, got: %v", err)
		}

		emptyUIDActor := BaseActor{
			ActorUID: "   ",
			Role:     RoleTeacher,
		}
		if err := emptyUIDActor.Validate(); !errors.Is(err, ErrEmptyActorUID) {
			t.Fatalf("expected ErrEmptyActorUID, got: %v", err)
		}

		invalidRoleActor := BaseActor{
			ActorUID: "USR-9b2f-48e1",
			Role:     "ESTUDIANTE_HACKER",
		}
		if err := invalidRoleActor.Validate(); !errors.Is(err, ErrInvalidActorRole) {
			t.Fatalf("expected ErrInvalidActorRole, got: %v", err)
		}
	})

	t.Run("AcademicContext validation", func(t *testing.T) {
		validCtx := AcademicContext{
			SubjectUID:  "SUB-MAT-101",
			Period:      "2026-1",
			CourseGroup: "G01",
		}
		if err := validCtx.Validate(); err != nil {
			t.Fatalf("expected valid context, got: %v", err)
		}

		invalidCtxList := []AcademicContext{
			{SubjectUID: "", Period: "2026-1", CourseGroup: "G01"},
			{SubjectUID: "SUB-MAT-101", Period: "", CourseGroup: "G01"},
			{SubjectUID: "SUB-MAT-101", Period: "2026-1", CourseGroup: ""},
		}
		for _, ctx := range invalidCtxList {
			if err := ctx.Validate(); err == nil {
				t.Fatalf("expected error for invalid context %+v, got nil", ctx)
			}
		}
	})

	t.Run("BaseAcademicEvent validation", func(t *testing.T) {
		now := time.Now().UTC()
		validEvent := BaseAcademicEvent{
			EventID:   "EVT-001",
			Type:      EventTypeRegistration,
			Timestamp: now,
			Actor: BaseActor{
				ActorUID: "USR-001",
				Role:     RoleTeacher,
			},
			Context: AcademicContext{
				SubjectUID:  "SUB-001",
				Period:      "2026-1",
				CourseGroup: "G01",
			},
		}
		if err := validEvent.Validate(); err != nil {
			t.Fatalf("expected valid event, got: %v", err)
		}

		// Empty EventID
		evt := validEvent
		evt.EventID = ""
		if err := evt.Validate(); !errors.Is(err, ErrEmptyEventID) {
			t.Fatalf("expected ErrEmptyEventID, got: %v", err)
		}

		// Invalid EventType
		evt = validEvent
		evt.Type = "INVALIDO"
		if err := evt.Validate(); !errors.Is(err, ErrInvalidEventType) {
			t.Fatalf("expected ErrInvalidEventType, got: %v", err)
		}

		// Zero Timestamp
		evt = validEvent
		evt.Timestamp = time.Time{}
		if err := evt.Validate(); !errors.Is(err, ErrZeroTimestamp) {
			t.Fatalf("expected ErrZeroTimestamp, got: %v", err)
		}

		// Invalid Actor
		evt = validEvent
		evt.Actor.ActorUID = ""
		if err := evt.Validate(); err == nil {
			t.Fatal("expected error on invalid actor, got nil")
		}

		// Invalid Context
		evt = validEvent
		evt.Context.SubjectUID = ""
		if err := evt.Validate(); err == nil {
			t.Fatal("expected error on invalid context, got nil")
		}
	})
}

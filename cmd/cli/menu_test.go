package main

import (
	"errors"
	"testing"

	"github.com/AlecAivazis/survey/v2/terminal"
)

// scriptedAsk simula al usuario devolviendo las respuestas en orden.
func scriptedAsk(answers ...MenuOption) func() (MenuOption, error) {
	return func() (MenuOption, error) {
		if len(answers) == 0 {
			return "", terminal.InterruptErr
		}
		next := answers[0]
		answers = answers[1:]
		return next, nil
	}
}

func TestRunMenuLoopDispatchesUntilExit(t *testing.T) {
	var calls []MenuOption
	record := func(o MenuOption) func() error {
		return func() error { calls = append(calls, o); return nil }
	}
	handlers := MenuHandlers{
		OptionGenerateEvents: record(OptionGenerateEvents),
		OptionEncryptLog:     record(OptionEncryptLog),
	}

	err := RunMenuLoop(scriptedAsk(OptionGenerateEvents, OptionEncryptLog, OptionExit, OptionGenerateEvents), handlers)
	if err != nil {
		t.Fatalf("RunMenuLoop failed: %v", err)
	}
	if len(calls) != 2 || calls[0] != OptionGenerateEvents || calls[1] != OptionEncryptLog {
		t.Errorf("unexpected dispatch order: %v", calls)
	}
}

func TestRunMenuLoopInterruptExitsCleanly(t *testing.T) {
	if err := RunMenuLoop(scriptedAsk(), MenuHandlers{}); err != nil {
		t.Errorf("Ctrl+C should exit without error, got %v", err)
	}
}

func TestRunMenuLoopHandlerErrorKeepsRunning(t *testing.T) {
	calls := 0
	handlers := MenuHandlers{OptionDecryptLog: func() error { calls++; return errors.New("boom") }}

	if err := RunMenuLoop(scriptedAsk(OptionDecryptLog, OptionDecryptLog, OptionExit), handlers); err != nil {
		t.Fatalf("RunMenuLoop failed: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected loop to continue after handler error, got %d calls", calls)
	}
}

func TestRunMenuLoopPropagatesPromptError(t *testing.T) {
	want := errors.New("stdin closed")
	ask := func() (MenuOption, error) { return "", want }
	if err := RunMenuLoop(ask, MenuHandlers{}); !errors.Is(err, want) {
		t.Errorf("expected prompt error, got %v", err)
	}
}

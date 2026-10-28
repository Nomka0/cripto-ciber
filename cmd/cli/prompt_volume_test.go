package main

import (
	"errors"
	"testing"
)

func TestPromptVolumeValidation(t *testing.T) {
	cases := []struct {
		input   string
		want    int
		wantErr error
	}{
		{"0", 0, ErrVolumeNotPositive},
		{"-5", 0, ErrVolumeNotPositive},
		{"abc", 0, ErrVolumeNotPositive},
		{"", 0, ErrVolumeNotPositive},
		{"3.5", 0, ErrVolumeNotPositive},
		{"100001", 0, ErrVolumeTooLarge},
		{"1", 1, nil},
		{" 50 ", 50, nil},
		{"100000", 100000, nil},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseEventVolume(tc.input)
			if !errors.Is(err, tc.wantErr) || got != tc.want {
				t.Errorf("ParseEventVolume(%q) = (%d, %v), want (%d, %v)", tc.input, got, err, tc.want, tc.wantErr)
			}
			if verr := ValidateEventVolume(tc.input); !errors.Is(verr, tc.wantErr) {
				t.Errorf("ValidateEventVolume(%q) = %v, want %v", tc.input, verr, tc.wantErr)
			}
		})
	}

	if err := ValidateEventVolume(42); err == nil {
		t.Errorf("ValidateEventVolume should reject non-string values")
	}
}

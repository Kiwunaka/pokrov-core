package ray2sing

import (
	"errors"
	"testing"
)

func TestLegacyAWGInputsAreBlocked(t *testing.T) {
	for name, parse := range map[string]func(string) error{
		"scheme": func(value string) error {
			_, err := rejectLegacyAWGConfig(value)
			return err
		},
		"text": func(value string) error {
			_, err := rejectLegacyAWGTextConfig(value)
			return err
		},
		"direct": func(value string) error {
			_, err := AWGSingbox(value)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := parse("awg://synthetic"); !errors.Is(err, errLegacyAWGConverterDisabled) {
				t.Fatalf("expected fail-closed AWG converter, got %v", err)
			}
		})
	}
}

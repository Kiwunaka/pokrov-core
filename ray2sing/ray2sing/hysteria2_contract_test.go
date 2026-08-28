package ray2sing

import (
	"errors"
	"testing"
)

func TestRawHysteria2URIsAreBlocked(t *testing.T) {
	for _, value := range []string{
		"hysteria2://synthetic@example.invalid:443",
		"hy2://synthetic@example.invalid:443",
	} {
		if _, err := Hysteria2Singbox(value); !errors.Is(err, errLegacyHY2ConverterDisabled) {
			t.Fatalf("expected fail-closed Hysteria2 converter, got %v", err)
		}
	}
}

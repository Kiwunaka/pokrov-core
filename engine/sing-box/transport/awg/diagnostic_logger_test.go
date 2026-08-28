package awg

import (
	"bytes"
	"context"
	"strings"
	"testing"

	boxLog "github.com/sagernet/sing-box/log"
)

func testSafeDeviceLogger(t *testing.T) (*bytes.Buffer, func(string, ...any), func(string, ...any)) {
	t.Helper()
	var output bytes.Buffer
	factory := boxLog.NewDefaultFactory(
		context.Background(),
		boxLog.Formatter{DisableColors: true, DisableTimestamp: true},
		&output,
		"",
		nil,
		false,
	)
	deviceLogger := newSafeDeviceLogger(factory.Logger())
	return &output, deviceLogger.Verbosef, deviceLogger.Errorf
}

func TestSafeDeviceLoggerClassifiesHandshakeRejectsWithoutFormattingArguments(t *testing.T) {
	output, verbosef, _ := testSafeDeviceLogger(t)
	rawEndpoint := "203.0.113.77:51820"
	rawPeer := "peer-secret-material"

	verbosef("Received message with unknown type")
	verbosef("Received packet with invalid mac1")
	verbosef("Received invalid response message from %s", rawEndpoint)
	verbosef("%v - Handshake did not complete after %d attempts, giving up", rawPeer, 9)

	logged := output.String()
	for _, code := range []string{
		"receive_unknown_type",
		"receive_invalid_mac1",
		"receive_invalid_response",
		"handshake_give_up",
	} {
		if !strings.Contains(logged, "awg_safe_diag code="+code+" occurrence=1") {
			t.Fatalf("missing safe diagnostic %q in %q", code, logged)
		}
	}
	if strings.Contains(logged, rawEndpoint) || strings.Contains(logged, rawPeer) {
		t.Fatalf("upstream formatting arguments leaked into safe diagnostics: %q", logged)
	}
}

func TestSafeDeviceLoggerBoundsEachCategory(t *testing.T) {
	output, verbosef, _ := testSafeDeviceLogger(t)
	for range maxSafeDiagnosticOccurrences + 3 {
		verbosef("Received packet with invalid mac1")
	}

	logged := output.String()
	if count := strings.Count(logged, "code=receive_invalid_mac1"); count != maxSafeDiagnosticOccurrences {
		t.Fatalf("diagnostic count = %d, want %d: %q", count, maxSafeDiagnosticOccurrences, logged)
	}
	if strings.Contains(logged, "occurrence=5") {
		t.Fatalf("diagnostic limit was exceeded: %q", logged)
	}
}

func TestSafeDeviceLoggerDropsUnclassifiedVerboseAndRedactsUnknownErrors(t *testing.T) {
	output, verbosef, errorf := testSafeDeviceLogger(t)
	rawEndpoint := "198.51.100.44:443"
	rawKey := "private-key-material"

	verbosef("Routine started at %s", rawEndpoint)
	errorf("unexpected upstream failure for %s with %s", rawEndpoint, rawKey)

	logged := output.String()
	if strings.Contains(logged, "routine started") {
		t.Fatalf("unclassified verbose message was emitted: %q", logged)
	}
	if !strings.Contains(logged, "awg_safe_diag code=upstream_error occurrence=1") {
		t.Fatalf("unknown error did not receive a fixed safe code: %q", logged)
	}
	if strings.Contains(logged, rawEndpoint) || strings.Contains(logged, rawKey) {
		t.Fatalf("unknown error arguments leaked into safe diagnostics: %q", logged)
	}
}

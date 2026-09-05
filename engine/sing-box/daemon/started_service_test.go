package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
)

type unreadyProbeEndpoint struct{ adapter.Endpoint }

func (unreadyProbeEndpoint) IsReady() bool { return false }

func TestEndpointCallCannotSucceedWithoutItsRuntime(t *testing.T) {
	s := NewStartedService(ServiceOptions{Context: context.Background(), LogMaxLines: 4})
	if healthy, err := s.ProbeEndpointResult("synthetic-target"); healthy || err == nil {
		t.Fatal("stopped runtime supplied endpoint proof")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.testSelectedEndpoint(&Instance{ctx: ctx}, unreadyProbeEndpoint{}) {
		t.Fatal("cancelled captured runtime supplied endpoint proof")
	}
}

func TestURLTestErrorCategory(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{name: "none", expected: "none"},
		{name: "deadline", err: context.DeadlineExceeded, expected: "deadline_exceeded"},
		{name: "cancelled", err: context.Canceled, expected: "context_canceled"},
		{name: "dns", err: errors.New("lookup example.test: no such host"), expected: "dns_lookup"},
		{name: "certificate", err: errors.New("x509: certificate has expired"), expected: "tls_certificate"},
		{name: "reality", err: errors.New("reality handshake failed"), expected: "reality_handshake"},
		{name: "http", err: errors.New("returned status 403"), expected: "http_rejected"},
		{name: "timeout", err: errors.New("read: i/o timeout"), expected: "io_timeout"},
		{name: "other", err: errors.New("broken transport"), expected: "transport_failure"},
		{name: "observed TLS timeout", err: &urltest.ProbeError{Stage: urltest.ProbeStageTLS, Err: context.DeadlineExceeded}, expected: "tls_timeout"},
		{name: "observed response timeout", err: &urltest.ProbeError{Stage: urltest.ProbeStageResponse, Err: context.DeadlineExceeded}, expected: "response_timeout"},
		{name: "wrapped certificate", err: &urltest.ProbeError{Stage: urltest.ProbeStageTLS, Err: errors.New("x509: synthetic certificate failure")}, expected: "tls_certificate"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := urlTestErrorCategory(test.err); actual != test.expected {
				t.Fatalf("unexpected category: got %q, want %q", actual, test.expected)
			}
		})
	}
}

func TestProbeEventUsesOnlyTypedCauseEvidence(t *testing.T) {
	if observedProbeErrorCode(&urltest.ProbeError{Stage: urltest.ProbeStageTLS, Err: context.DeadlineExceeded}) != "TRANSPORT-006" {
		t.Fatal("observed TLS timeout was not retained in the probe event")
	}
	if observedProbeErrorCode(errors.New("lookup dns.example.test: synthetic failure")) != "EGRESS-001" {
		t.Fatal("legacy diagnostic text was promoted to a causal event")
	}
}

func TestCanonicalAWGSafeDiagnostic(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		expected string
		accepted bool
	}{
		{
			name:     "formatted safe diagnostic",
			message:  "WARN[0007] endpoint/awg[test]: awg_safe_diag code=handshake_retry occurrence=2",
			expected: "awg_safe_diag code=handshake_retry occurrence=2",
			accepted: true,
		},
		{
			name:     "all bounded occurrences",
			message:  "awg_safe_diag code=receive_handshake_response occurrence=4",
			expected: "awg_safe_diag code=receive_handshake_response occurrence=4",
			accepted: true,
		},
		{name: "unknown code", message: "awg_safe_diag code=peer_secret occurrence=1"},
		{name: "zero occurrence", message: "awg_safe_diag code=handshake_retry occurrence=0"},
		{name: "unbounded occurrence", message: "awg_safe_diag code=handshake_retry occurrence=5"},
		{name: "trailing material", message: "awg_safe_diag code=handshake_retry occurrence=1 secret"},
		{name: "newline", message: "awg_safe_diag code=handshake_retry occurrence=1\n"},
		{name: "ordinary log", message: "service started"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, accepted := canonicalAWGSafeDiagnostic(test.message)
			if accepted != test.accepted || actual != test.expected {
				t.Fatalf(
					"unexpected classification: got (%q, %t), want (%q, %t)",
					actual,
					accepted,
					test.expected,
					test.accepted,
				)
			}
		})
	}
}

func TestReleaseStartedServiceForwardsOnlyCanonicalAWGSafeDiagnostic(t *testing.T) {
	handler := &recordingPlatformHandler{}
	service := NewStartedService(ServiceOptions{
		Handler:     handler,
		Debug:       false,
		LogMaxLines: 8,
	})

	service.WriteMessage(
		log.LevelWarn,
		"WARN[0007] endpoint/awg[test]: awg_safe_diag code=receive_invalid_mac1 occurrence=1",
	)
	service.WriteMessage(
		log.LevelWarn,
		"WARN[0007] endpoint/awg[test]: peer=secret awg_safe_diag code=unknown occurrence=1",
	)
	service.WriteMessage(
		log.LevelError,
		"ERROR[0007] endpoint/awg[test]: awg_safe_diag code=receive_error occurrence=1",
	)

	if len(handler.debugMessages) != 1 {
		t.Fatalf("unexpected forwarded message count: got %d, want 1", len(handler.debugMessages))
	}
	if handler.debugMessages[0] != "awg_safe_diag code=receive_invalid_mac1 occurrence=1" {
		t.Fatalf("unexpected forwarded message: %q", handler.debugMessages[0])
	}
}

type recordingPlatformHandler struct {
	debugMessages []string
}

func (h *recordingPlatformHandler) ServiceStop() error { return nil }

func (h *recordingPlatformHandler) ServiceReload() error { return nil }

func (h *recordingPlatformHandler) SystemProxyStatus() (*SystemProxyStatus, error) {
	return &SystemProxyStatus{}, nil
}

func (h *recordingPlatformHandler) SetSystemProxyEnabled(bool) error { return nil }

func (h *recordingPlatformHandler) WriteDebugMessage(message string) {
	h.debugMessages = append(h.debugMessages, message)
}

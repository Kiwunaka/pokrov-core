package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestStartedServiceCloseEndsObserversAndRejectsReuse(t *testing.T) {
	s := NewStartedService(ServiceOptions{Context: context.Background(), LogMaxLines: 4})
	_, statusDone, _ := s.serviceStatusObserver.Subscribe()
	_, logDone, _ := s.logObserver.Subscribe()
	_, urlDone, _ := s.urlTestObserver.Subscribe()
	_, clashDone, _ := s.clashModeObserver.Subscribe()
	_, connectionDone, _ := s.connectionEventObserver.Subscribe()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan struct{}{statusDone, logDone, urlDone, clashDone, connectionDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("terminal close left an observer subscription alive")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("repeated terminal close failed: %v", err)
	}
	if err := s.StartOrReloadServiceOptions(option.Options{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed service accepted reuse: %v", err)
	}
}

type unreadyProbeEndpoint struct{ adapter.Endpoint }

type stalledTLSProbeEndpoint struct {
	adapter.Endpoint
	conn net.Conn
}

func (stalledTLSProbeEndpoint) IsReady() bool { return true }

func (e stalledTLSProbeEndpoint) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return e.conn, nil
}

func TestSelectedEndpointDeadlineRetainsTLSStage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	client, server := net.Pipe()
	defer server.Close()
	go io.Copy(io.Discard, server) // Receive ClientHello without replying.
	s := NewStartedService(ServiceOptions{Context: ctx, LogMaxLines: 4})
	defer s.Close()
	if s.testSelectedEndpoint(&Instance{ctx: ctx}, stalledTLSProbeEndpoint{conn: client}) {
		t.Fatal("stalled TLS negotiation supplied egress proof")
	}
	entry := s.logLines.Back()
	if entry == nil || entry.Value.Message != "selected endpoint URL test failed category=tls_timeout" {
		t.Fatal("endpoint deadline discarded the observed TLS stage")
	}
}

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

func TestManagedLoggerDoesNotRetainPlantedMaterialInAnyLogSink(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(map[bool]string{false: "release", true: "debug"}[debug], func(t *testing.T) {
			handler := &recordingPlatformHandler{}
			service := NewStartedService(ServiceOptions{
				Context: context.Background(), Handler: handler, Debug: debug, LogMaxLines: 8,
			})
			var output bytes.Buffer
			factory := log.NewDefaultFactory(context.Background(), log.Formatter{
				DisableColors: true, DisableTimestamp: true,
			}, &output, "", service, true)
			defer factory.Close()
			factoryEntries, _, err := factory.Subscribe()
			if err != nil {
				t.Fatal(err)
			}
			defer factory.UnSubscribe(factoryEntries)
			serviceEntries, _, err := service.logObserver.Subscribe()
			if err != nil {
				t.Fatal(err)
			}
			defer service.logObserver.UnSubscribe(serviceEntries)
			const planted = "PLANTED-PRIVATE-MATERIAL"
			logger := factory.NewLogger(planted)
			messages := []string{
				"outbound failed: Authorization: Bearer " + planted,
				planted + " awg_safe_diag code=handshake_retry occurrence=1",
				"awg_safe_diag code=handshake_retry occurrence=1 token=" + planted,
				"selected endpoint URL test failed category=tls_certificate",
				"selected endpoint URL test failed category=tls_certificate token=" + planted,
			}
			expected := []string{
				"runtime_log_redacted",
				"awg_safe_diag code=handshake_retry occurrence=1",
				"runtime_log_redacted",
				"selected endpoint URL test failed category=tls_certificate",
				"runtime_log_redacted",
			}
			for index, message := range messages {
				logger.Warn(message)
				select {
				case entry := <-factoryEntries:
					if strings.Contains(entry.Message, planted) {
						t.Fatal("factory subscription retained planted material")
					}
				case <-time.After(time.Second):
					t.Fatal("factory log subscription did not settle")
				}
				select {
				case entry := <-serviceEntries:
					if strings.Contains(entry.Message, planted) {
						t.Fatal("native service subscription retained planted material")
					}
					if entry.Message != expected[index] {
						t.Fatal("managed log lost its closed diagnostic category")
					}
				case <-time.After(time.Second):
					t.Fatal("native service log subscription did not settle")
				}
			}
			if strings.Contains(output.String(), planted) || strings.Contains(strings.Join(handler.debugMessages, "\n"), planted) {
				t.Fatal("writer or host callback retained planted material")
			}
			service.WriteMessage(log.LevelError, planted)
			for entry := service.logLines.Front(); entry != nil; entry = entry.Next() {
				if strings.Contains(entry.Value.Message, planted) {
					t.Fatal("native replay buffer retained planted material")
				}
			}
		})
	}
}

func TestManagedLoggerKeepsPanicSemanticsWithSafePayload(t *testing.T) {
	service := NewStartedService(ServiceOptions{
		Context: context.Background(), Handler: &recordingPlatformHandler{}, LogMaxLines: 1,
	})
	var output bytes.Buffer
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{}, &output, "", service, false)
	defer factory.Close()
	defer func() {
		recovered := recover()
		message, ok := recovered.(string)
		if !ok || !strings.Contains(message, "runtime_log_redacted") || strings.Contains(message, "PLANTED-PRIVATE-MATERIAL") {
			t.Fatal("managed logger did not preserve panic with a safe payload")
		}
	}()
	factory.Logger().Panic("PLANTED-PRIVATE-MATERIAL")
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

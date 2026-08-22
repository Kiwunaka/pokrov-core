package libbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	operationalTestRunID     = "018f4f2a-6d58-4c11-8c27-4fb77bd28c15"
	operationalTestAttemptID = "57ba1c00-f8a9-4b76-a3dc-d44a6d7cff33"
)

type recordingOperationalHandler struct {
	lock   sync.Mutex
	events []*OperationalEvent
	ready  chan struct{}
}

func (h *recordingOperationalHandler) WriteOperationalEvent(event *OperationalEvent) {
	h.lock.Lock()
	h.events = append(h.events, event)
	h.lock.Unlock()
	h.ready <- struct{}{}
}

func TestOperationalEmitterUsesClosedSafeFields(t *testing.T) {
	emitter := newOperationalEventEmitter()
	defer emitter.close()
	handler := &recordingOperationalHandler{ready: make(chan struct{}, 8)}
	emitter.setHandler(handler)
	if err := emitter.configure(operationalTestRunID, operationalTestAttemptID, 9); err != nil {
		t.Fatal(err)
	}
	if !emitter.emit("core.runtime.start", "start", "core_start", "failed", "CORE-006") {
		t.Fatal("expected event to be accepted")
	}
	waitForOperationalEvents(t, handler.ready, 1)
	handler.lock.Lock()
	defer handler.lock.Unlock()
	event := handler.events[0]
	if event.Sequence != 1 || event.Generation != 9 || event.ErrorCode != "CORE-006" ||
		event.SchemaVersion != 1 || event.EventABI != 1 {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestOperationalEmitterRejectsUnknownAndStaleInput(t *testing.T) {
	emitter := newOperationalEventEmitter()
	defer emitter.close()
	emitter.setHandler(&recordingOperationalHandler{ready: make(chan struct{}, 1)})
	if err := emitter.configure(operationalTestRunID, operationalTestAttemptID, 4); err != nil {
		t.Fatal(err)
	}
	if err := emitter.configure(operationalTestRunID, operationalTestAttemptID, 3); err == nil {
		t.Fatal("expected stale generation to fail")
	}
	if emitter.emit("core.raw.line", "start", "core_start", "failed", "CORE-006") {
		t.Fatal("unknown event crossed emitter")
	}
	if emitter.emit("core.runtime.start", "start", "core_start", "failed", "RAW-001") {
		t.Fatal("unknown code crossed emitter")
	}
}

func TestOperationalClassifierDoesNotForwardRawFailure(t *testing.T) {
	rawCorpus := []string{
		`{"server":"vpn.example.test","password":"hunter2"}`,
		"203.0.113.42:443",
		"https://private.example.test/path?token=secret",
		"Authorization: Bearer planted-secret",
	}
	for _, raw := range rawCorpus {
		code := classifyOperationalStartError(errors.New("dial failed: " + raw))
		if code != "CORE-006" {
			t.Fatalf("unexpected code %q", code)
		}
		if strings.Contains(fmt.Sprintf("%q", code), raw) {
			t.Fatalf("raw failure crossed classifier: %q", raw)
		}
	}
}

func TestOperationalClassifierKeepsTransportClassesDistinct(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
	}{
		{name: "deadline", err: context.DeadlineExceeded, code: "TRANSPORT-001"},
		{name: "typed timeout", err: &net.DNSError{Err: "temporary transport stall", IsTimeout: true}, code: "TRANSPORT-001"},
		{name: "refused", err: fmt.Errorf("dial failed: %w", syscall.ECONNREFUSED), code: "TRANSPORT-002"},
		{name: "authentication", err: errors.New("proxy authentication failed"), code: "TRANSPORT-003"},
		{name: "protocol", err: errors.New("TLS protocol version mismatch"), code: "TRANSPORT-004"},
		{name: "configuration", err: errors.New("invalid profile config"), code: "CORE-005"},
		{name: "generic transport", err: errors.New("network is unreachable"), code: "CORE-006"},
		{name: "unknown", err: errors.New("unexpected start failure"), code: "CORE-003"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if code := classifyOperationalStartError(test.err); code != test.code {
				t.Fatalf("expected %s, got %s", test.code, code)
			}
		})
	}
}

func TestOperationalEmitterIsConcurrentAndBounded(t *testing.T) {
	emitter := newOperationalEventEmitter()
	defer emitter.close()
	blocked := make(chan struct{})
	emitter.setHandler(operationalBlockingHandler{blocked: blocked})
	if err := emitter.configure(operationalTestRunID, operationalTestAttemptID, 1); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	started := time.Now()
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := 0; index < 1000; index++ {
				emitter.emit("core.runtime.start", "start", "core_start", "started", "")
			}
		}()
	}
	group.Wait()
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("producer blocked for %s", elapsed)
	}
	close(blocked)
}

type operationalBlockingHandler struct {
	blocked <-chan struct{}
}

func (h operationalBlockingHandler) WriteOperationalEvent(*OperationalEvent) {
	<-h.blocked
}

func waitForOperationalEvents(t *testing.T, ready <-chan struct{}, count int) {
	t.Helper()
	for index := 0; index < count; index++ {
		select {
		case <-ready:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
}

package observability

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
	testRunID     = "018f4f2a-6d58-4c11-8c27-4fb77bd28c15"
	testAttemptID = "57ba1c00-f8a9-4b76-a3dc-d44a6d7cff33"
)

func TestEmitterProducesClosedCorrelatedEvents(t *testing.T) {
	emitter := NewEmitter(8)
	var (
		lock   sync.Mutex
		events []Event
	)
	delivered := make(chan struct{}, 2)
	emitter.SetSink(func(event Event) {
		lock.Lock()
		events = append(events, event)
		lock.Unlock()
		delivered <- struct{}{}
	})
	if err := emitter.Configure(testRunID, testAttemptID, 7); err != nil {
		t.Fatal(err)
	}
	if !emitter.Emit(RuntimeStart, OutcomeStarted, "") ||
		!emitter.Emit(RuntimeStart, OutcomeSucceeded, "") {
		t.Fatal("expected both events to be accepted")
	}
	waitForEvents(t, delivered, 2)

	lock.Lock()
	defer lock.Unlock()
	if len(events) != 2 || events[0].Sequence != 1 || events[1].Sequence != 2 {
		t.Fatalf("unexpected sequence: %#v", events)
	}
	for _, event := range events {
		if event.SchemaVersion != 1 || event.EventABI != 1 ||
			event.RunID != testRunID || event.AttemptID != testAttemptID ||
			event.Generation != 7 || event.Phase != "core_start" {
			t.Fatalf("unexpected event: %#v", event)
		}
	}
}

func TestEmitterRejectsStaleContextAndUnknownValues(t *testing.T) {
	emitter := NewEmitter(1)
	emitter.SetSink(func(Event) {})
	if err := emitter.Configure(testRunID, testAttemptID, 4); err != nil {
		t.Fatal(err)
	}
	if err := emitter.Configure(testRunID, testAttemptID, 3); err == nil {
		t.Fatal("expected stale generation to fail")
	}
	if emitter.Emit(Definition{Name: "raw.line"}, OutcomeFailed, "CORE-003") {
		t.Fatal("unknown event definition crossed the emitter")
	}
	if emitter.Emit(RuntimeStart, OutcomeFailed, "UNKNOWN-001") {
		t.Fatal("unknown error code crossed the emitter")
	}
	if emitter.Emit(RuntimeStart, OutcomeSucceeded, "CORE-003") {
		t.Fatal("successful event carried an error code")
	}
}

func TestRawFailureCorpusCannotCrossEventABI(t *testing.T) {
	secrets := []string{
		`{"outbounds":[{"server":"vpn.example.test","password":"hunter2"}]}`,
		"203.0.113.42:443",
		"https://private.example.test/path?token=secret",
		"Authorization: Bearer planted-secret",
		`C:\\Users\\alice\\AppData\\Local\\POKROV\\managed-profile.json`,
	}
	emitter := NewEmitter(16)
	delivered := make(chan Event, len(secrets))
	emitter.SetSink(func(event Event) { delivered <- event })
	if err := emitter.Configure(testRunID, testAttemptID, 1); err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		err := errors.New("dial failed: " + secret)
		if !emitter.Emit(RuntimeStart, OutcomeFailed, ClassifyStartError(err)) {
			t.Fatal("expected classified event")
		}
	}
	for range secrets {
		select {
		case event := <-delivered:
			encoded := fmt.Sprintf("%+v", event)
			for _, secret := range secrets {
				if strings.Contains(encoded, secret) {
					t.Fatalf("raw material crossed ABI: %q", secret)
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
}

func TestStartFailureClassifierKeepsTransportClassesDistinct(t *testing.T) {
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
			if code := ClassifyStartError(test.err); code != test.code {
				t.Fatalf("expected %s, got %s", test.code, code)
			}
		})
	}
}

func TestEmitterDoesNotBlockWhenSinkIsStalled(t *testing.T) {
	emitter := NewEmitter(1)
	blocked := make(chan struct{})
	emitter.SetSink(func(Event) { <-blocked })
	if err := emitter.Configure(testRunID, testAttemptID, 1); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	for index := 0; index < 10000; index++ {
		emitter.Emit(RuntimeStart, OutcomeStarted, "")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("producer blocked for %s", elapsed)
	}
	if emitter.Snapshot().Dropped == 0 {
		t.Fatal("expected bounded queue pressure to be observable")
	}
	close(blocked)
}

func TestEmitterIsRaceSafe(t *testing.T) {
	emitter := NewEmitter(MaximumPendingEvents)
	emitter.SetSink(func(Event) {})
	if err := emitter.Configure(testRunID, testAttemptID, 1); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := 0; index < 1000; index++ {
				emitter.Emit(RuntimeStart, OutcomeStarted, "")
			}
		}()
	}
	group.Wait()
	if emitter.Snapshot().Sequence != 8000 {
		t.Fatalf("unexpected final sequence: %d", emitter.Snapshot().Sequence)
	}
}

func waitForEvents(t *testing.T, delivered <-chan struct{}, count int) {
	t.Helper()
	for index := 0; index < count; index++ {
		select {
		case <-delivered:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
}

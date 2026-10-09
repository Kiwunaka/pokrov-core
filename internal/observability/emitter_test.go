package observability

import (
	"errors"
	"fmt"
	"strings"
	"sync"
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

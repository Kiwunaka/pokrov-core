package libbox

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
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

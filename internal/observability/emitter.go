package observability

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Sink func(Event)

type Snapshot struct {
	Generation int64
	Sequence   int64
	Enqueued   uint64
	Dropped    uint64
	Delivered  uint64
	Panics     uint64
}

type Emitter struct {
	lock       sync.RWMutex
	sink       Sink
	runID      string
	attemptID  string
	generation int64
	sequence   int64
	pending    chan Event
	enqueued   atomic.Uint64
	dropped    atomic.Uint64
	delivered  atomic.Uint64
	panics     atomic.Uint64
}

func NewEmitter(maximumPending int) *Emitter {
	if maximumPending < 1 || maximumPending > MaximumPendingEvents {
		maximumPending = MaximumPendingEvents
	}
	emitter := &Emitter{pending: make(chan Event, maximumPending)}
	go emitter.deliver()
	return emitter
}

func (e *Emitter) SetSink(sink Sink) {
	e.lock.Lock()
	e.sink = sink
	e.lock.Unlock()
}

func (e *Emitter) Configure(runID string, attemptID string, generation int64) error {
	if !uuidPattern.MatchString(runID) {
		return errors.New("invalid run identifier")
	}
	if !uuidPattern.MatchString(attemptID) {
		return errors.New("invalid attempt identifier")
	}
	if generation < 1 || generation > int64(^uint32(0)>>1) {
		return errors.New("invalid generation")
	}

	e.lock.Lock()
	defer e.lock.Unlock()
	if generation < e.generation {
		return errors.New("stale generation")
	}
	if generation > e.generation {
		e.sequence = 0
	}
	e.runID = runID
	e.attemptID = attemptID
	e.generation = generation
	return nil
}

func (e *Emitter) Emit(definition Definition, outcome Outcome, errorCode string) bool {
	severity, valid := validateEvent(definition, outcome, errorCode)
	if !valid {
		return false
	}

	e.lock.Lock()
	if e.sink == nil || e.generation < 1 {
		e.lock.Unlock()
		return false
	}
	e.sequence++
	event := Event{
		SchemaVersion: SchemaVersion,
		EventABI:      EventABIVersion,
		OccurredAtUTC: time.Now().UTC(),
		RunID:         e.runID,
		AttemptID:     e.attemptID,
		Generation:    e.generation,
		Sequence:      e.sequence,
		Name:          definition.Name,
		Subsystem:     definition.Subsystem,
		Stage:         definition.Stage,
		Severity:      severity,
		Outcome:       outcome,
		ErrorCode:     errorCode,
		Phase:         definition.Phase,
	}
	e.lock.Unlock()

	select {
	case e.pending <- event:
		e.enqueued.Add(1)
		return true
	default:
		e.dropped.Add(1)
		return false
	}
}

func (e *Emitter) Snapshot() Snapshot {
	e.lock.RLock()
	generation := e.generation
	sequence := e.sequence
	e.lock.RUnlock()
	return Snapshot{
		Generation: generation,
		Sequence:   sequence,
		Enqueued:   e.enqueued.Load(),
		Dropped:    e.dropped.Load(),
		Delivered:  e.delivered.Load(),
		Panics:     e.panics.Load(),
	}
}

func (e *Emitter) deliver() {
	for event := range e.pending {
		e.lock.RLock()
		sink := e.sink
		e.lock.RUnlock()
		if sink == nil {
			continue
		}
		func() {
			defer func() {
				if recover() != nil {
					e.panics.Add(1)
				}
			}()
			sink(event)
			e.delivered.Add(1)
		}()
	}
}

func validateEvent(definition Definition, outcome Outcome, errorCode string) (Severity, bool) {
	if definition != RuntimeInitialize && definition != RuntimeStart &&
		definition != RuntimeStop && definition != EgressProbe {
		return "", false
	}
	if outcome != OutcomeStarted && outcome != OutcomeSucceeded && outcome != OutcomeFailed {
		return "", false
	}
	if outcome == OutcomeFailed {
		if !isKnownErrorCode(errorCode) {
			return "", false
		}
		return SeverityError, true
	}
	if errorCode != "" {
		return "", false
	}
	return SeverityInfo, true
}

func isKnownErrorCode(code string) bool {
	switch code {
	case "CORE-003", "CORE-005", "CORE-006", "CORE-008", "EGRESS-001",
		"TRANSPORT-001", "TRANSPORT-002", "TRANSPORT-003", "TRANSPORT-004":
		return true
	default:
		return false
	}
}

func ClassifyStartError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "TRANSPORT-001"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "TRANSPORT-001"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "TRANSPORT-002"
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"timeout", "timed out", "deadline exceeded",
	} {
		if strings.Contains(message, marker) {
			return "TRANSPORT-001"
		}
	}
	for _, marker := range []string{
		"connection refused", "actively refused",
	} {
		if strings.Contains(message, marker) {
			return "TRANSPORT-002"
		}
	}
	for _, marker := range []string{
		"authentication", "unauthorized", "forbidden", "invalid credential",
		"bad credential", "access denied", "permission denied",
	} {
		if strings.Contains(message, marker) {
			return "TRANSPORT-003"
		}
	}
	for _, marker := range []string{
		"handshake", "protocol negotiation", "protocol version", "tls alert", "alpn", "unexpected eof",
		"malformed response", "version mismatch",
	} {
		if strings.Contains(message, marker) {
			return "TRANSPORT-004"
		}
	}
	for _, marker := range []string{
		"config", "parse", "unknown field", "unsupported option",
		"invalid option", "invalid profile",
	} {
		if strings.Contains(message, marker) {
			return "CORE-005"
		}
	}
	for _, marker := range []string{
		"transport", "dial", "connect", "network is unreachable",
		"connection reset", "no route to host", "broken pipe",
	} {
		if strings.Contains(message, marker) {
			return "CORE-006"
		}
	}
	return "CORE-003"
}

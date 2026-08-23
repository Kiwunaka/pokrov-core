package libbox

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	OperationalEventSchemaVersion = 1
	OperationalEventABIVersion    = 1
	operationalEventQueueSize     = 128
)

var operationalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type OperationalEvent struct {
	SchemaVersion int32
	EventABI      int32
	OccurredAtUTC string
	RunID         string
	AttemptID     string
	Generation    int64
	Sequence      int64
	Name          string
	Subsystem     string
	Stage         string
	Severity      string
	Outcome       string
	ErrorCode     string
	Phase         string
}

type OperationalEventHandler interface {
	WriteOperationalEvent(event *OperationalEvent)
}

type operationalEventEmitter struct {
	lock       sync.RWMutex
	handler    OperationalEventHandler
	runID      string
	attemptID  string
	generation int64
	sequence   int64
	pending    chan *OperationalEvent
	stopped    bool
}

func newOperationalEventEmitter() *operationalEventEmitter {
	emitter := &operationalEventEmitter{
		pending: make(chan *OperationalEvent, operationalEventQueueSize),
	}
	go emitter.deliver()
	return emitter
}

func (e *operationalEventEmitter) setHandler(handler OperationalEventHandler) {
	e.lock.Lock()
	e.handler = handler
	e.lock.Unlock()
}

func (e *operationalEventEmitter) configure(runID string, attemptID string, generation int64) error {
	if !operationalUUIDPattern.MatchString(runID) {
		return errors.New("invalid run identifier")
	}
	if !operationalUUIDPattern.MatchString(attemptID) {
		return errors.New("invalid attempt identifier")
	}
	if generation < 1 || generation > int64(^uint32(0)>>1) {
		return errors.New("invalid generation")
	}

	e.lock.Lock()
	defer e.lock.Unlock()
	if e.stopped {
		return errors.New("event emitter stopped")
	}
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

func (e *operationalEventEmitter) emit(name string, stage string, phase string, outcome string, errorCode string) bool {
	if !validOperationalEvent(name, stage, phase, outcome, errorCode) {
		return false
	}
	e.lock.Lock()
	defer e.lock.Unlock()
	if e.stopped || e.handler == nil || e.generation < 1 {
		return false
	}
	e.sequence++
	severity := "info"
	if outcome == "failed" {
		severity = "error"
	}
	event := &OperationalEvent{
		SchemaVersion: OperationalEventSchemaVersion,
		EventABI:      OperationalEventABIVersion,
		OccurredAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
		RunID:         e.runID,
		AttemptID:     e.attemptID,
		Generation:    e.generation,
		Sequence:      e.sequence,
		Name:          name,
		Subsystem:     "core",
		Stage:         stage,
		Severity:      severity,
		Outcome:       outcome,
		ErrorCode:     errorCode,
		Phase:         phase,
	}
	select {
	case e.pending <- event:
		return true
	default:
		return false
	}
}

func (e *operationalEventEmitter) close() {
	e.lock.Lock()
	if !e.stopped {
		e.stopped = true
		e.handler = nil
		close(e.pending)
	}
	e.lock.Unlock()
}

func (e *operationalEventEmitter) deliver() {
	for event := range e.pending {
		e.lock.RLock()
		handler := e.handler
		e.lock.RUnlock()
		if handler == nil {
			continue
		}
		func() {
			defer func() { _ = recover() }()
			handler.WriteOperationalEvent(event)
		}()
	}
}

func validOperationalEvent(name string, stage string, phase string, outcome string, errorCode string) bool {
	validDefinition :=
		(name == "core.runtime.start" && stage == "start" && phase == "core_start") ||
			(name == "core.runtime.stop" && stage == "stop" && phase == "stop") ||
			(name == "core.egress.probe" && stage == "verify" && phase == "egress")
	if !validDefinition {
		return false
	}
	if outcome != "started" && outcome != "succeeded" && outcome != "failed" {
		return false
	}
	if outcome != "failed" {
		return errorCode == ""
	}
	return errorCode == "CORE-003" || errorCode == "CORE-005" ||
		errorCode == "CORE-006" || errorCode == "CORE-008" ||
		errorCode == "EGRESS-001" || errorCode == "TRANSPORT-001" ||
		errorCode == "TRANSPORT-002" || errorCode == "TRANSPORT-003" ||
		errorCode == "TRANSPORT-004"
}

func classifyOperationalStartError(err error) string {
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

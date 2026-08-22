package observability

import "time"

const (
	SchemaVersion        = 1
	EventABIVersion      = 1
	MaximumPendingEvents = 128
)

type Severity string

const (
	SeverityInfo  Severity = "info"
	SeverityError Severity = "error"
)

type Outcome string

const (
	OutcomeStarted   Outcome = "started"
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
)

type Definition struct {
	Name      string
	Subsystem string
	Stage     string
	Phase     string
}

var (
	RuntimeInitialize = Definition{
		Name:      "core.runtime.initialize",
		Subsystem: "core",
		Stage:     "initialize",
		Phase:     "initialization",
	}
	RuntimeStart = Definition{
		Name:      "core.runtime.start",
		Subsystem: "core",
		Stage:     "start",
		Phase:     "core_start",
	}
	RuntimeStop = Definition{
		Name:      "core.runtime.stop",
		Subsystem: "core",
		Stage:     "stop",
		Phase:     "stop",
	}
	EgressProbe = Definition{
		Name:      "core.egress.probe",
		Subsystem: "egress",
		Stage:     "verify",
		Phase:     "egress",
	}
)

type Event struct {
	SchemaVersion int
	EventABI      int
	OccurredAtUTC time.Time
	RunID         string
	AttemptID     string
	Generation    int64
	Sequence      int64
	Name          string
	Subsystem     string
	Stage         string
	Severity      Severity
	Outcome       Outcome
	ErrorCode     string
	Phase         string
}

func (e Event) OccurredAtRFC3339() string {
	return e.OccurredAtUTC.UTC().Format(time.RFC3339Nano)
}

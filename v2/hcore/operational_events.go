package hcore

import "github.com/Kiwunaka/POKROV-core/internal/observability"

type OperationalEvent = observability.Event

var operationalEventEmitter = observability.NewEmitter(observability.MaximumPendingEvents)

func SetOperationalEventSink(sink func(OperationalEvent)) {
	operationalEventEmitter.SetSink(sink)
}

func ConfigureOperationalEventContext(runID string, attemptID string, generation int64) error {
	return operationalEventEmitter.Configure(runID, attemptID, generation)
}

func emitOperationalEvent(definition observability.Definition, outcome observability.Outcome, errorCode string) {
	operationalEventEmitter.Emit(definition, outcome, errorCode)
}

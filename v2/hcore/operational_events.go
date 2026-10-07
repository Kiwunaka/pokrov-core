package hcore

import (
	"context"
	"errors"

	"github.com/Kiwunaka/POKROV-core/internal/observability"
	"github.com/sagernet/sing-box/adapter"
)

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

func newOwnedDNSProbeTrace() adapter.OwnedDNSProbeTrace {
	emit := operationalEventEmitter.CaptureContext()
	if emit == nil {
		return nil
	}
	return func(ctx context.Context, stage adapter.OwnedDNSProbeStage, err error) bool {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return false
		}
		definition := observability.DNSProbeReceive
		outcome := observability.OutcomeStarted
		switch stage {
		case adapter.OwnedDNSProbeReceive:
		case adapter.OwnedDNSProbeExchange:
			definition = observability.DNSProbeExchange
			outcome = observability.OutcomeSucceeded
		case adapter.OwnedDNSProbeReply:
			definition = observability.DNSProbeReply
			outcome = observability.OutcomeSucceeded
		default:
			return false
		}
		code := ""
		if err != nil {
			outcome = observability.OutcomeFailed
			code = "DNS-002"
		}
		return emit(definition, outcome, code)
	}
}

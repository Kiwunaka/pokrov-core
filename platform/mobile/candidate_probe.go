package mobile

import (
	"time"

	"github.com/Kiwunaka/POKROV-core/v2/hcore"
	"github.com/sagernet/sing-box/experimental/libbox"
)

type CandidateProbeCancellation interface {
	IsCancelled() bool
}

func ProbeCandidate(configJSON, probeID string, timeoutMs int32, platformInterface libbox.PlatformInterface, cancellation CandidateProbeCancellation) string {
	if platformInterface == nil || cancellation == nil {
		return (hcore.CandidateProbeResult{FailureKind: "invalid_request"}).JSON()
	}
	return hcore.ProbeCandidate(configJSON, probeID, time.Duration(timeoutMs)*time.Millisecond,
		"", platformInterface, cancellation.IsCancelled).JSON()
}

func CancelCandidateProbe(probeID string) {
	hcore.CancelCandidateProbe(probeID)
}

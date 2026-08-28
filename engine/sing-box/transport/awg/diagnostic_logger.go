package awg

import (
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/sagernet/sing/common/logger"
)

const maxSafeDiagnosticOccurrences = 4

type safeDeviceLogAdapter struct {
	logger logger.ContextLogger
	mutex  sync.Mutex
	counts map[string]uint8
}

func newSafeDeviceLogger(parent logger.ContextLogger) *device.Logger {
	adapter := &safeDeviceLogAdapter{
		logger: parent,
		counts: make(map[string]uint8),
	}
	return &device.Logger{
		Verbosef: adapter.verbosef,
		Errorf:   adapter.errorf,
	}
}

func (a *safeDeviceLogAdapter) verbosef(format string, _ ...any) {
	code, emit := classifySafeDeviceVerbose(format)
	if !emit {
		return
	}
	a.emit(code)
}

func (a *safeDeviceLogAdapter) errorf(format string, _ ...any) {
	a.emit(classifySafeDeviceError(format))
}

func (a *safeDeviceLogAdapter) emit(code string) {
	a.mutex.Lock()
	count := a.counts[code]
	if count >= maxSafeDiagnosticOccurrences {
		a.mutex.Unlock()
		return
	}
	count++
	a.counts[code] = count
	a.mutex.Unlock()

	// Only fixed classifier output and a bounded counter leave this adapter.
	// Upstream formatting arguments can contain endpoint or peer material and
	// are deliberately never formatted.
	a.logger.Warn("awg_safe_diag code=", code, " occurrence=", count)
}

func classifySafeDeviceVerbose(format string) (string, bool) {
	message := strings.ToLower(format)
	switch {
	case strings.Contains(message, "received message with unknown type"):
		return "receive_unknown_type", true
	case strings.Contains(message, "received packet with invalid mac1"):
		return "receive_invalid_mac1", true
	case strings.Contains(message, "received invalid response message"):
		return "receive_invalid_response", true
	case strings.Contains(message, "failed to decode response message"):
		return "receive_decode_response", true
	case strings.Contains(message, "received handshake response"):
		return "receive_handshake_response", true
	case strings.Contains(message, "sending handshake initiation"):
		return "send_handshake_initiation", true
	case strings.Contains(message, "handshake did not complete") && strings.Contains(message, "giving up"):
		return "handshake_give_up", true
	case strings.Contains(message, "handshake did not complete"):
		return "handshake_retry", true
	default:
		return "", false
	}
}

func classifySafeDeviceError(format string) string {
	message := strings.ToLower(format)
	switch {
	case strings.Contains(message, "failed to receive") || strings.Contains(message, "read packet"):
		return "receive_error"
	case strings.Contains(message, "failed to send handshake"):
		return "send_handshake_error"
	case strings.Contains(message, "failed to decode response"):
		return "receive_decode_response"
	default:
		return "upstream_error"
	}
}

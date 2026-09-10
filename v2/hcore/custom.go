package hcore

import (
	"github.com/Kiwunaka/POKROV-core/internal/observability"
	"github.com/Kiwunaka/POKROV-core/v2/config"
	"github.com/sagernet/sing-box/log"
)

// runtimeFailure keeps the typed cause for internal errors.Is/errors.As while
// exposing only a catalog code through logs, status observers and platform ABIs.
type runtimeFailure struct {
	code  string
	cause error
}

func (e *runtimeFailure) Error() string { return e.code }
func (e *runtimeFailure) Unwrap() error { return e.cause }

func errorWrapper(state MessageType, err error) (*CoreInfoResponse, error) {
	safe := &runtimeFailure{code: observability.ClassifyStartError(err), cause: err}
	Log(LogLevel_FATAL, LogType_CORE, safe.Error())
	StopAndAlert(MessageType_UNEXPECTED_ERROR, safe.Error())
	return SetCoreStatus(CoreStates_STOPPED, state, safe.Error()), safe
}

func StopAndAlert(msgType MessageType, message string) {
	SetCoreStatus(CoreStates_STOPPED, msgType, message)

	if ss := static.StartedService; ss != nil {
		ss.Close()
		static.StartedService = nil
	}
}

func Close(mode SetupMode) error {
	defer config.DeferPanicToError("close", func(err error) {
		Log(LogLevel_FATAL, LogType_CORE, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})
	log.Debug("[Service] Closing")

	_, err := Stop()
	CloseGrpcServer(mode)

	return err
}

// func (s *CoreService) Status(ctx context.Context, empty *hcommon.Empty) (*CoreInfoResponse, error) {
// 	return Status()
// }

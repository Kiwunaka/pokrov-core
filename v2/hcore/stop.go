package hcore

import (
	"context"
	"fmt"

	"github.com/Kiwunaka/POKROV-core/internal/observability"
	"github.com/Kiwunaka/POKROV-core/v2/config"
	hcommon "github.com/Kiwunaka/POKROV-core/v2/hcommon"
)

func (s *CoreService) Stop(ctx context.Context, empty *hcommon.Empty) (*CoreInfoResponse, error) {
	return Stop()
}

func Stop() (coreResponse *CoreInfoResponse, err error) {
	emitOperationalEvent(observability.RuntimeStop, observability.OutcomeStarted, "")
	defer func() {
		if err != nil {
			emitOperationalEvent(observability.RuntimeStop, observability.OutcomeFailed, "CORE-008")
			return
		}
		emitOperationalEvent(observability.RuntimeStop, observability.OutcomeSucceeded, "")
	}()
	defer config.DeferPanicToError("stop", func(recovered_err error) {
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})

	// if static.CoreState != CoreStates_STARTED {
	// 	return errorWrapper(MessageType_INSTANCE_NOT_STARTED, fmt.Errorf("instance not started"))
	// }
	// if static.Box == nil {
	// 	return errorWrapper(MessageType_INSTANCE_NOT_FOUND, fmt.Errorf("instance not found"))
	// }
	static.lock.Lock()
	defer static.lock.Unlock()

	SetCoreStatus(CoreStates_STOPPING, MessageType_EMPTY, "")
	ss := static.StartedService
	if ss == nil {
		return SetCoreStatus(CoreStates_STOPPED, MessageType_ALREADY_STOPPED, ""), nil
	}

	if err := ss.CloseService(); err != nil {
		static.StartedService = nil
		dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-stop.log"))
		return errorWrapper(MessageType_UNEXPECTED_ERROR, err)
	}
	// err = common.Close(static.StartedService)
	static.StartedService = nil

	return SetCoreStatus(CoreStates_STOPPED, MessageType_EMPTY, ""), nil
}

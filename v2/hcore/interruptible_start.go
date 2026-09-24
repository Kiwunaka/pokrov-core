package hcore

import (
	"context"
	"time"
)

// StartInterruptible cancels context-aware startup work without racing Stop
// against Start. The caller owns serialized rollback after this method returns.
// interrupted is never called after return, including on an error or panic.
func StartInterruptible(base context.Context, request *StartRequest, interrupted func() bool) (response *CoreInfoResponse, err error) {
	ctx, cancel := context.WithCancel(base)
	finished := make(chan struct{})
	joined := make(chan struct{})
	if interrupted() {
		cancel()
	}
	go func() {
		defer close(joined)
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-finished:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if interrupted() {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		close(finished)
		<-joined
		if err == nil {
			err = ctx.Err()
		}
		// A successful instance owns its context until serialized Stop. Do not
		// cancel it merely because the synchronous start call finished.
		if response == nil || err != nil {
			cancel()
		}
	}()
	response, err = Start(ctx, request)
	return response, err
}

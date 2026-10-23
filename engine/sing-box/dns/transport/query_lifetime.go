package transport

import (
	"context"
	"net"
	"sync"
)

// queryLifetime also owns single-use DNS connections and reuse probes, which
// are deliberately not registered in the shared connection pool.
type queryLifetime struct {
	access sync.Mutex
	active map[*queryCancellation]struct{}
	closed bool
}

type queryCancellation struct {
	cancel context.CancelCauseFunc
}

func newQueryLifetime() *queryLifetime {
	return &queryLifetime{active: make(map[*queryCancellation]struct{})}
}

func (l *queryLifetime) bind(parent context.Context) (context.Context, func(), error) {
	l.access.Lock()
	defer l.access.Unlock()
	if l.closed {
		return nil, nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancelCause(parent)
	if cause := context.Cause(ctx); cause != nil {
		cancel(cause)
		return nil, nil, cause
	}
	entry := &queryCancellation{cancel: cancel}
	l.active[entry] = struct{}{}
	return ctx, func() {
		l.access.Lock()
		delete(l.active, entry)
		l.access.Unlock()
		cancel(context.Canceled)
	}, nil
}

func (l *queryLifetime) reset() {
	l.access.Lock()
	if l.closed {
		l.access.Unlock()
		return
	}
	// Cancel synchronously while serializing Reset/Close. AfterFunc-only
	// propagation could let a late dial write after transport teardown returns.
	for entry := range l.active {
		entry.cancel(net.ErrClosed)
	}
	l.active = make(map[*queryCancellation]struct{})
	l.access.Unlock()
}

func (l *queryLifetime) close() {
	l.access.Lock()
	if l.closed {
		l.access.Unlock()
		return
	}
	l.closed = true
	for entry := range l.active {
		entry.cancel(net.ErrClosed)
	}
	l.active = nil
	l.access.Unlock()
}

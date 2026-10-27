package localdpi

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// Embedding only net.Conn keeps buffer/syscall/unwrap fast paths behind these
// Read and Write methods. Remote bytes are not a decrypted protocol proof.
type observedConn struct {
	net.Conn
	ctx       context.Context
	owner     *Outbound
	wrote     atomic.Bool
	responded atomic.Bool
	closed    atomic.Bool
	once      sync.Once
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.responded.Store(true)
	}
	// Browsers can open speculative TCP sockets without sending a request.
	// A read failure before any client payload has not exercised the strategy.
	if c.wrote.Load() {
		c.observe(err, failureEarlyRead)
	}
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	if c.owner.admission.Load() == admissionWithdrawn || c.ctx.Err() != nil {
		return 0, errUnavailable
	}
	if len(p) > 0 {
		c.wrote.Store(true)
	}
	n, err := c.Conn.Write(p)
	c.observe(err, failureEarlyWrite)
	return n, err
}

func (c *observedConn) observe(err error, reason admissionFailure) {
	if err != nil && !c.responded.Load() && !c.closed.Load() && c.ctx.Err() == nil &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		c.owner.failAdmission(reason)
	}
}

func (c *observedConn) Close() error {
	c.closed.Store(true)
	var err error
	c.once.Do(func() { err = c.Conn.Close() })
	return err
}

type flow struct {
	client    net.Conn
	cancel    context.CancelFunc
	mu        sync.Mutex
	remote    net.Conn
	closed    bool
	local     bool // guarded by Outbound.mu; excludes ordinary VPN streams
	closeOnce sync.Once
}

func (f *flow) attach(remote net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		_ = remote.Close()
		return false
	}
	f.remote = remote
	return true
}

func (f *flow) close() {
	f.mu.Lock()
	f.closed = true
	remote := f.remote
	f.mu.Unlock()
	// Competing cancellation/withdrawal callers join the same completed close.
	f.closeOnce.Do(func() {
		f.cancel()
		if remote != nil {
			_ = remote.Close()
		}
		_ = f.client.Close()
	})
}

package localdpi

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const firstResponseTimeout = 5 * time.Second

// Embedding only net.Conn keeps buffer/syscall/unwrap fast paths behind these
// Read and Write methods. Remote bytes are not a decrypted protocol proof.
type observedConn struct {
	net.Conn
	ctx         context.Context
	owner       *Outbound
	admissionID string
	wrote       atomic.Bool
	responded   atomic.Bool
	closed      atomic.Bool
	once        sync.Once
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.responded.Load() {
		c.owner.mu.Lock()
		if !c.responded.Swap(true) && c.wrote.Load() {
			_ = c.Conn.SetReadDeadline(time.Time{})
		}
		c.owner.mu.Unlock()
	}
	// Browsers can open speculative TCP sockets without sending a request.
	// A read failure before any client payload has not exercised the strategy.
	if c.wrote.Load() {
		c.observe(err, failureEarlyRead)
	}
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	c.owner.mu.Lock()
	available := c.owner.admissionID == c.admissionID && c.owner.admission.Load() != admissionWithdrawn
	if !available || c.ctx.Err() != nil {
		c.owner.mu.Unlock()
		return 0, errUnavailable
	}
	var deadlineErr error
	if len(p) > 0 && !c.wrote.Load() {
		// A reader may already be waiting. Arm the deadline only when the
		// client uses this socket. The first response takes the same lock.
		c.wrote.Store(true)
		if !c.responded.Load() {
			deadlineErr = c.Conn.SetReadDeadline(time.Now().Add(firstResponseTimeout))
		}
	}
	c.owner.mu.Unlock()
	if deadlineErr != nil {
		c.observe(deadlineErr, failureEarlyWrite)
		return 0, deadlineErr
	}
	n, err := c.Conn.Write(p)
	if c.wrote.Load() {
		c.observe(err, failureEarlyWrite)
	}
	return n, err
}

func (c *observedConn) observe(err error, reason admissionFailure) {
	if err != nil && !c.responded.Load() && !c.closed.Load() && c.ctx.Err() == nil &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		c.owner.failAdmission(c.admissionID, reason)
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

package localdpi

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const firstResponseTimeout = 5 * time.Second

// Embedding only net.Conn keeps buffer/syscall/unwrap fast paths behind these
// Read and Write methods. Remote bytes are not a decrypted protocol proof.
type observedConn struct {
	net.Conn
	ctx                   context.Context
	owner                 *Outbound
	admissionID           string
	callerReadDeadline    time.Time // guarded by owner.mu
	firstResponseDeadline time.Time // guarded by owner.mu
	wrote                 atomic.Bool
	responded             atomic.Bool
	closed                atomic.Bool
	once                  sync.Once
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.responded.Load() {
		c.owner.mu.Lock()
		if !c.responded.Swap(true) && !c.firstResponseDeadline.IsZero() {
			c.firstResponseDeadline = time.Time{}
			_ = c.Conn.SetReadDeadline(c.callerReadDeadline)
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
			c.firstResponseDeadline = time.Now().Add(firstResponseTimeout)
			deadlineErr = c.Conn.SetReadDeadline(c.effectiveReadDeadline(c.callerReadDeadline))
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

func (c *observedConn) SetDeadline(deadline time.Time) error {
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	if err := c.setCallerReadDeadline(deadline); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *observedConn) SetReadDeadline(deadline time.Time) error {
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	return c.setCallerReadDeadline(deadline)
}

func (c *observedConn) setCallerReadDeadline(deadline time.Time) error {
	if err := c.Conn.SetReadDeadline(c.effectiveReadDeadline(deadline)); err != nil {
		return err
	}
	c.callerReadDeadline = deadline
	return nil
}

func (c *observedConn) effectiveReadDeadline(caller time.Time) time.Time {
	if !c.firstResponseDeadline.IsZero() && (caller.IsZero() || c.firstResponseDeadline.Before(caller)) {
		return c.firstResponseDeadline
	}
	return caller
}

func (c *observedConn) observe(err error, reason admissionFailure) {
	if err != nil && !c.responded.Load() && !c.closed.Load() && c.ctx.Err() == nil &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		cause := ""
		if reason == failureEarlyRead {
			var netError net.Error
			switch {
			case errors.As(err, &netError) && netError.Timeout():
				cause = "timeout"
			case errors.Is(err, syscall.ECONNRESET):
				cause = "reset"
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				cause = "remote_closed"
			default:
				cause = "other"
			}
		}
		c.owner.failAdmission(c.admissionID, reason, cause)
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

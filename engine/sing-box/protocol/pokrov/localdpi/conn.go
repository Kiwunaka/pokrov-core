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
	admission *atomic.Uint32
	responded atomic.Bool
	closed    atomic.Bool
	once      sync.Once
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.responded.Store(true)
	}
	c.observe(err)
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	if c.admission.Load() == admissionWithdrawn || c.ctx.Err() != nil {
		return 0, errUnavailable
	}
	n, err := c.Conn.Write(p)
	c.observe(err)
	return n, err
}

func (c *observedConn) observe(err error) {
	if err != nil && !c.responded.Load() && !c.closed.Load() && c.ctx.Err() == nil &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		c.admission.CompareAndSwap(admissionReady, admissionFailed)
	}
}

func (c *observedConn) Close() error {
	c.closed.Store(true)
	var err error
	c.once.Do(func() { err = c.Conn.Close() })
	return err
}

type flow struct {
	client net.Conn
	cancel context.CancelFunc
	mu     sync.Mutex
	remote net.Conn
	closed bool
	local  bool // guarded by Outbound.mu; excludes ordinary VPN streams
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
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	remote := f.remote
	f.mu.Unlock()
	f.cancel()
	if remote != nil {
		_ = remote.Close()
	}
	_ = f.client.Close()
}

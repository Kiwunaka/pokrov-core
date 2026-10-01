package telegramws

import (
	"context"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"
)

func (h *Outbound) connectGateway(ctx context.Context, dc *datacenter) (net.Conn, error) {
	tlsConfig, err := tls.NewClient(ctx, h.logger, dc.host, option.OutboundTLSOptions{
		Enabled: true, ServerName: dc.host, ALPN: []string{"http/1.1"},
	})
	if err != nil {
		return nil, err
	}
	conn, err := tls.NewDialer(h.dialer, tlsConfig).DialContext(ctx, N.NetworkTCP, dc.address)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	reader, handshake, err := (ws.Dialer{Protocols: []string{"binary"}}).Upgrade(conn,
		&url.URL{Scheme: "wss", Host: dc.host, Path: "/apiws"})
	stopCancel()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if handshake.Protocol != "binary" || ctx.Err() != nil {
		_ = conn.Close()
		return nil, errScope
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reader != nil && reader.Buffered() > 0 {
		buffer := buf.NewSize(reader.Buffered())
		if _, err := buffer.ReadFullFrom(reader, buffer.Len()); err != nil {
			buffer.Release()
			_ = conn.Close()
			return nil, err
		}
		conn = bufio.NewCachedConn(conn, buffer)
	}
	return &gatewayConn{Conn: v2raywebsocket.NewConn(conn, dc.address, ws.StateClientSide), raw: conn,
		failed: func() { h.markUnavailable(dc) }}, nil
}

// Closing the runtime must close its socket immediately. A graceful WS close
// must not wait for a blocked write or race with the connection manager's copy.
type gatewayConn struct {
	net.Conn
	raw    net.Conn
	once   sync.Once
	closed atomic.Bool
	failed func()
}

func (c *gatewayConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil && !c.closed.Load() {
		c.failed()
	}
	return n, err
}

func (c *gatewayConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil && !c.closed.Load() {
		c.failed()
	}
	return n, err
}

func (c *gatewayConn) Close() error {
	var err error
	c.closed.Store(true)
	c.once.Do(func() { err = c.raw.Close() })
	return err
}

// ConnectionManager can copy cached initialization without a context check.
// Preserve this wrapper through handoff so every MTProto write consults the
// same terminal admission latch that owns and closes the attached WSS socket.
type admittedConn struct {
	net.Conn
	owner *Outbound
	flow  *telegramFlow
}

func (c *admittedConn) Write(p []byte) (int, error) {
	c.owner.mu.Lock()
	current := c.owner.currentLocked()
	var cleanup func()
	if !current {
		cleanup = c.owner.denyLocked()
	}
	allowed := current && c.owner.admitted && c.flow.commitPayload()
	c.owner.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
	if !allowed {
		return 0, errClosed
	}
	return c.Conn.Write(p)
}

type telegramFlow struct {
	mu                                                                        sync.Mutex
	client, remote                                                            net.Conn
	ctx                                                                       context.Context
	cancel                                                                    context.CancelFunc
	reading, active, closed, vpnTransferred, payloadCommitted, setupWithdrawn bool
}

func (f *telegramFlow) attach(remote net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.setupWithdrawn || f.ctx.Err() != nil || remote == nil {
		return false
	}
	f.remote, f.active = remote, true
	return true
}

func (f *telegramFlow) withdraw() {
	f.mu.Lock()
	if f.vpnTransferred {
		f.mu.Unlock()
		return
	}
	f.setupWithdrawn = true
	active := f.active
	if f.reading {
		_ = f.client.SetReadDeadline(time.Now())
	}
	f.mu.Unlock()
	if active {
		f.close()
	}
}

func (f *telegramFlow) close() {
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

func (f *telegramFlow) transferVPN() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.active || f.payloadCommitted {
		return false
	}
	f.vpnTransferred = true
	return true
}

func (f *telegramFlow) commitPayload() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || !f.active || f.vpnTransferred || f.ctx.Err() != nil {
		return false
	}
	// Linearize the first payload attempt under the same owner lock as deny.
	// Denial closes an accepted in-flight write; it never replays it to VPN.
	f.payloadCommitted = true
	return true
}

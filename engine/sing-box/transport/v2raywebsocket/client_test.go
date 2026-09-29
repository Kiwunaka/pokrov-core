package v2raywebsocket

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type pipeDialer struct{ conn net.Conn }

type closeTrackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (d pipeDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (pipeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unused")
}

func TestEarlyConnectionCloseUnblocksRead(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	tracked := &closeTrackedConn{Conn: raw}
	client, err := NewClient(context.Background(), pipeDialer{tracked}, M.ParseSocksaddr("127.0.0.1:8080"), option.V2RayWebsocketOptions{MaxEarlyData: 2048}, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		read <- err
	}()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-read:
		if err != net.ErrClosed {
			t.Fatalf("read after close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("early-data read remained blocked after close")
	}
	if !tracked.closed.Load() {
		t.Fatal("underlying connection was not closed")
	}
}

package v2rayhttpupgrade

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type closeTrackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type pipeDialer struct{ conn net.Conn }

func (d pipeDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (pipeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unused")
}

func TestRejectedUpgradeClosesConnection(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	tracked := &closeTrackedConn{Conn: raw}
	client, err := NewClient(context.Background(), pipeDialer{tracked}, M.ParseSocksaddr("127.0.0.1:8080"), option.V2RayHTTPUpgradeOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if _, err := http.ReadRequest(bufio.NewReader(peer)); err == nil {
			fmt.Fprint(peer, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		}
	}()
	if _, err := client.DialContext(context.Background()); err == nil {
		t.Fatal("rejected upgrade succeeded")
	}
	if !tracked.closed.Load() {
		t.Fatal("rejected upgrade leaked its connection")
	}
}

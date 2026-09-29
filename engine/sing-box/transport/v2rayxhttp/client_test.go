package xhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type loopbackDialer struct{ net.Dialer }

func (d *loopbackDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, address.String())
}

func TestStreamOneHTTP2ReuseAndClientReset(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != "/test/" {
			t.Errorf("unexpected XHTTP request: %s %s %s", r.Proto, r.Method, r.URL.Path)
			return
		}
		buffer := make([]byte, 32)
		for {
			n, err := r.Body.Read(buffer)
			if n > 0 {
				_, _ = w.Write(buffer[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tlsConfig, err := tls.NewClient(ctx, logger.NOP(), "test.invalid", option.OutboundTLSOptions{
		Enabled: true, Insecure: true, ServerName: "test.invalid", ALPN: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, &loopbackDialer{}, M.ParseSocksaddr(strings.TrimPrefix(server.URL, "https://")),
		option.V2RayXHTTPOptions{Mode: "stream-one", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{Path: "/test"}}, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	exchange := func(conn net.Conn, payload string) {
		t.Helper()
		if _, writeErr := io.WriteString(conn, payload); writeErr != nil {
			t.Fatal(writeErr)
		}
		reply := make([]byte, len(payload))
		if _, readErr := io.ReadFull(conn, reply); readErr != nil || string(reply) != payload {
			t.Fatalf("stream exchange failed: %q, %v", reply, readErr)
		}
	}
	dialCtx, dialCancel := context.WithCancel(ctx)
	defer dialCancel()
	first, err := client.DialContext(dialCtx)
	if err != nil {
		t.Fatal(err)
	}
	exchange(first, "first")
	dialCancel()
	exchange(first, "still-open")
	first.Close()
	second, err := client.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exchange(second, "second")
	client.Close()
	if _, err = second.Read(make([]byte, 1)); err == nil {
		t.Fatal("client close did not stop its active stream")
	}
	second.Close()
	// VLESS.InterfaceUpdated reuses its transport after calling Close.
	third, err := client.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	exchange(third, "after-reset")
}

func (*loopbackDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("TCP-only test")
}

func TestStreamOneCancellationClosesPendingTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	closed := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
		// Receive the ClientHello but never answer it.
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	tlsConfig, err := tls.NewClient(ctx, logger.NOP(), "test.invalid", option.OutboundTLSOptions{
		Enabled: true, ServerName: "test.invalid", ALPN: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, &loopbackDialer{}, M.ParseSocksaddr(listener.Addr().String()),
		option.V2RayXHTTPOptions{Mode: "stream-one", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{Path: "/test"}}, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, _ := client.DialContext(ctx)
	if conn != nil {
		_ = conn.Close()
	}
	select {
	case serverConn := <-accepted:
		defer serverConn.Close()
	case <-time.After(time.Second):
		t.Fatal("loopback connection was not accepted")
	}
	select {
	case <-closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("XHTTP TLS socket survived candidate cancellation")
	}
}

func TestXmuxMaxConnectionsBoundsPendingTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	tlsConfig, err := tls.NewClient(ctx, logger.NOP(), "test.invalid", option.OutboundTLSOptions{
		Enabled: true, ServerName: "test.invalid", ALPN: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, &loopbackDialer{}, M.ParseSocksaddr(listener.Addr().String()),
		option.V2RayXHTTPOptions{Mode: "stream-one", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
			Path: "/test", Xmux: &option.V2RayXHTTPXmuxOptions{MaxConnections: badoption.Range{From: 2, To: 2}},
		}}, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var sessions sync.WaitGroup
	for range 12 {
		sessions.Go(func() {
			conn, _ := client.DialContext(ctx)
			if conn != nil {
				_ = conn.Close()
			}
		})
	}
	sessions.Wait()
	if count := accepted.Load(); count != 2 {
		t.Fatalf("xmux maxConnections=2 opened %d pending TLS sockets", count)
	}
}

func TestXmuxRotationKeepsActiveStreamsAndReleasesClients(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buffer := make([]byte, 32)
		for {
			n, err := r.Body.Read(buffer)
			if n > 0 {
				_, _ = w.Write(buffer[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tlsConfig, err := tls.NewClient(ctx, logger.NOP(), "test.invalid", option.OutboundTLSOptions{
		Enabled: true, Insecure: true, ServerName: "test.invalid", ALPN: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewClient(ctx, &loopbackDialer{}, M.ParseSocksaddr(strings.TrimPrefix(server.URL, "https://")),
		option.V2RayXHTTPOptions{Mode: "stream-one", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
			Path: "/test", Xmux: &option.V2RayXHTTPXmuxOptions{
				MaxConnections: badoption.Range{From: 1, To: 1}, HMaxRequestTimes: badoption.Range{From: 1, To: 1},
			},
		}}, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	client := transport.(*Client)
	defer client.Close()
	dial := func() net.Conn {
		t.Helper()
		conn, err := client.DialContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	exchange := func(conn net.Conn) {
		t.Helper()
		if _, err := io.WriteString(conn, "test"); err != nil {
			t.Fatal(err)
		}
		var reply [4]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "test" {
			t.Fatalf("rotated stream stopped working: %v", err)
		}
	}
	first := dial()
	defer first.Close()
	exchange(first)
	second := dial()
	exchange(second)
	_ = second.Close()
	exchange(first) // Retirement must preserve an established stream.
	_ = first.Close()
	for range 8 {
		conn := dial()
		exchange(conn)
		_ = conn.Close()
		client.clientsMu.Lock()
		retained := len(client.clients)
		client.clientsMu.Unlock()
		if retained != 1 {
			t.Fatalf("rotation retained %d HTTP clients, want one reusable client", retained)
		}
	}
}

package xhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
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

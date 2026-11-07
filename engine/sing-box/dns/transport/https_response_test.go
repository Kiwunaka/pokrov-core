package transport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

type countedDNSBody struct {
	remaining int
	read      int
	failure   error
}

func (b *countedDNSBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		if b.failure != nil {
			return 0, b.failure
		}
		return 0, io.EOF
	}
	n := min(len(p), b.remaining)
	for i := range p[:n] {
		p[i] = 0xa5
	}
	b.remaining -= n
	b.read += n
	return n, nil
}

func (*countedDNSBody) Close() error { return nil }

func TestReadDNSMessageBodyBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length int64
		size   int
		want   error
		read   int
	}{
		{"known_limit", 65535, 65535, nil, 65535},
		{"unknown_limit", -1, 65535, nil, 65535},
		{"zero_length_limit", 0, 65535, nil, 65535},
		{"known_oversize", 65536, 65536, errDNSMessageTooLarge, 0},
		{"huge_declared_length", math.MaxInt64, 0, errDNSMessageTooLarge, 0},
		{"unknown_oversize", -1, 1 << 20, errDNSMessageTooLarge, 65536},
		{"zero_length_oversize", 0, 1 << 20, errDNSMessageTooLarge, 65536},
		{"misreported_oversize", 12, 1 << 20, errDNSMessageTooLarge, 65536},
		{"truncated", 12, 11, io.ErrUnexpectedEOF, 11},
		{"empty_unknown", -1, 0, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &countedDNSBody{remaining: tc.size}
			got, err := readDNSMessageBody(&http.Response{ContentLength: tc.length, Body: body})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if body.read != tc.read {
				t.Fatalf("read %d bytes, want %d", body.read, tc.read)
			}
			if err != nil && got != nil {
				t.Fatal("failed response returned partial payload")
			}
			if err == nil && len(got) != tc.size {
				t.Fatalf("payload size = %d, want %d", len(got), tc.size)
			}
		})
	}
}

func TestReadDNSMessageBodyReadFailure(t *testing.T) {
	failure := errors.New("synthetic read failure")
	body := &countedDNSBody{remaining: 13, failure: failure}
	got, err := readDNSMessageBody(&http.Response{ContentLength: -1, Body: body})
	if !errors.Is(err, failure) || got != nil {
		t.Fatalf("got %d bytes, %v; partial response must be discarded", len(got), err)
	}
}

func TestReadDNSMessageBodyPreservesWireBytes(t *testing.T) {
	// A complete DNS response: one question and one compressed A answer.
	wire := []byte{
		0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		1, 'a', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1,
		0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1,
	}
	for _, length := range []int64{-1, int64(len(wire))} {
		got, err := readDNSMessageBody(&http.Response{
			ContentLength: length, Body: io.NopCloser(bytes.NewReader(wire)),
		})
		if err != nil || !bytes.Equal(got, wire) {
			t.Fatalf("wire payload changed: %v", err)
		}
	}
}

type httpsReadinessTestDialer struct {
	N.Dialer
	conn net.Conn
	err  error
	ctx  context.Context
}

func (d *httpsReadinessTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.ctx = ctx
	return d.conn, d.err
}

type httpsReadinessTestTLSConfig struct {
	tls.Config
	err error
}

func (*httpsReadinessTestTLSConfig) HandshakeTimeout() time.Duration { return 0 }
func (c *httpsReadinessTestTLSConfig) ClientHandshake(_ context.Context, conn net.Conn) (tls.Conn, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &httpsReadinessTestTLSConn{conn}, nil
}

type httpsReadinessTestTLSConn struct{ net.Conn }

func (c *httpsReadinessTestTLSConn) NetConn() net.Conn                    { return c.Conn }
func (*httpsReadinessTestTLSConn) HandshakeContext(context.Context) error { return nil }
func (*httpsReadinessTestTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{NegotiatedProtocol: "http/1.1"}
}

func TestHTTPSReadinessTransportFailures(t *testing.T) {
	newTransport := func(raw N.Dialer, config tls.Config) *HTTPSTransport {
		transport := NewHTTPSRaw(dns.NewTransportAdapter("https", "readiness", nil), nil, raw,
			&url.URL{Scheme: "https", Host: "resolver.test", Path: "/dns-query"}, make(http.Header),
			M.Socksaddr{Fqdn: "resolver.test", Port: 443}, config)
		t.Cleanup(func() { _ = transport.Close() })
		return transport
	}
	exchange := func(transport *HTTPSTransport) (string, error) {
		var reason string
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ctx = adapter.ContextWithDNSReadinessObserver(ctx, func(_ adapter.DNSTransport, _ time.Time, _ time.Duration, _ error, hint string) {
			reason = hint
		})
		message := new(mDNS.Msg)
		message.SetQuestion("service.test.", mDNS.TypeA)
		_, err := transport.Exchange(ctx, message)
		return reason, err
	}
	t.Run("dial", func(t *testing.T) {
		failure := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
		transport := newTransport(&httpsReadinessTestDialer{err: failure}, &httpsReadinessTestTLSConfig{})
		reason, err := exchange(transport)
		var networkError net.Error
		if err != failure || !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatal("readiness changed the original transport error or net.Error semantics")
		}
		if reason != "doh_dial" {
			t.Fatal("endpoint dial failure lost its closed DoH reason")
		}
	})
	t.Run("tls", func(t *testing.T) {
		conn, peer := net.Pipe()
		defer peer.Close()
		failure := errors.New("synthetic handshake failure")
		transport := newTransport(&httpsReadinessTestDialer{conn: conn}, &httpsReadinessTestTLSConfig{err: failure})
		if reason, err := exchange(transport); reason != "doh_tls" || err != failure {
			t.Fatal("TLS failure lost its phase or changed its original error")
		}
	})
	checkHTTP := func(t *testing.T, response, want string) {
		conn, peer := net.Pipe()
		defer conn.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer peer.Close()
			request, err := http.ReadRequest(bufio.NewReader(peer))
			if err == nil {
				_, _ = io.Copy(io.Discard, request.Body)
				_ = request.Body.Close()
				_, _ = io.WriteString(peer, response)
			}
		}()
		transport := newTransport(&httpsReadinessTestDialer{conn: conn}, &httpsReadinessTestTLSConfig{})
		transport.fallback.Store(true) // Exercise the existing HTTP/1 path with an in-memory connection.
		reason, err := exchange(transport)
		if err == nil || reason != want {
			t.Fatal("HTTP failure lost its directly observed phase")
		}
		<-done
	}
	t.Run("http_exchange", func(t *testing.T) { checkHTTP(t, "", "doh_http_exchange") })
	t.Run("http_status", func(t *testing.T) {
		checkHTTP(t, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "doh_http_status")
	})
	t.Run("no_observer", func(t *testing.T) {
		failure := errors.New("synthetic dial failure")
		raw := &httpsReadinessTestDialer{err: failure}
		transport := newTransport(raw, &httpsReadinessTestTLSConfig{})
		if _, err := transport.Exchange(context.Background(), new(mDNS.Msg)); err != failure {
			t.Fatal("ordinary exchange changed its error")
		}
		if raw.ctx.Value(httpsReadinessKey{}) != nil || raw.ctx.Value(httpsDialAttemptKey{}) != nil {
			t.Fatal("ordinary exchange acquired readiness metadata")
		}
	})
}

func TestHTTPSReadinessRejectsAmbiguousOrLateEvidence(t *testing.T) {
	failure := errors.New("synthetic dial failure")
	attempt := &httpsDialAttempt{endpointCalls: 1, endpointError: failure}
	var reused httpsReadiness
	if reused.freeze(failure) != "" { // A pooled/shared dial belonged to another exchange.
		t.Fatal("reused connection acquired another exchange's phase")
	}
	var multiple httpsReadiness
	multiple.beginAttempt()
	multiple.beginAttempt()
	multiple.completeAttempt(attempt, failure, false)
	if multiple.freeze(failure) != "" {
		t.Fatal("multiple dials acquired a unique phase")
	}
	var repeatedEndpoint httpsReadiness
	repeatedEndpoint.beginAttempt()
	repeated := new(httpsDialAttempt)
	dialCtx := context.WithValue(context.Background(), httpsDialAttemptKey{}, repeated)
	observedDialer := &httpsReadinessDialer{&httpsReadinessTestDialer{err: failure}}
	for range 2 { // The existing TLS dialer may redial once after ECH rejection.
		if _, err := observedDialer.DialContext(dialCtx, "tcp", M.Socksaddr{}); err != failure {
			t.Fatal("raw redial changed the original error")
		}
	}
	repeatedEndpoint.completeAttempt(repeated, failure, false)
	if repeatedEndpoint.freeze(failure) != "" {
		t.Fatal("an internal TLS redial acquired a unique phase")
	}
	var mismatched httpsReadiness
	mismatched.beginAttempt()
	mismatched.completeAttempt(attempt, failure, false)
	if mismatched.freeze(io.EOF) != "" {
		t.Fatal("a different returned error acquired a dial phase")
	}
	var late httpsReadiness
	late.beginAttempt()
	if late.freeze(failure) != "" {
		t.Fatal("pending dial acquired a terminal phase")
	}
	late.completeAttempt(attempt, failure, false)
	if late.beginAttempt() || late.freeze(failure) != "" {
		t.Fatal("late evidence changed a frozen exchange")
	}
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	raw := &httpsReadinessTestDialer{conn: conn}
	if got, err := (&httpsReadinessDialer{raw}).DialContext(context.Background(), "tcp", M.Socksaddr{}); got != conn || err != nil {
		t.Fatal("endpoint observation changed the original connection")
	}
}

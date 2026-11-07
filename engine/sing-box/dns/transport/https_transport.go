package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var errFallback = E.New("fallback to HTTP/1.1")

type httpsReadinessKey struct{}
type httpsDialAttemptKey struct{}

// Only the exchange that owns one completed dial can attribute its failure.
// Reused/shared connections and retries retain no inferred substage.
type httpsReadiness struct {
	mu         sync.Mutex
	frozen     bool
	attempts   int
	dialError  error
	dialReason string
	connected  bool
}

type httpsDialAttempt struct {
	endpointCalls int
	endpointError error
}

type httpsReadinessDialer struct{ N.Dialer }

func (d *httpsReadinessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if attempt, _ := ctx.Value(httpsDialAttemptKey{}).(*httpsDialAttempt); attempt != nil {
		attempt.endpointCalls++
		attempt.endpointError = err
	}
	return conn, err
}

func (d *httpsReadinessDialer) Upstream() any { return d.Dialer }

func (o *httpsReadiness) beginAttempt() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.frozen {
		return false
	}
	o.attempts++
	return true
}

func (o *httpsReadiness) completeAttempt(attempt *httpsDialAttempt, err error, connected bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.frozen || o.attempts != 1 || attempt.endpointCalls > 1 {
		return
	}
	o.dialError, o.connected = err, connected
	if err != nil && attempt.endpointCalls == 1 {
		if attempt.endpointError == nil {
			o.dialReason = "doh_tls"
		} else if errors.Is(err, attempt.endpointError) {
			o.dialReason = "doh_dial"
		}
	}
}

func (o *httpsReadiness) freeze(err error) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.frozen = true
	if err == nil || o.attempts != 1 {
		return ""
	}
	if o.dialError != nil {
		if errors.Is(err, o.dialError) {
			return o.dialReason
		}
		return ""
	}
	if o.connected {
		return "doh_http_exchange"
	}
	return ""
}

type HTTPSTransportWrapper struct {
	http2Transport *http2.Transport
	httpTransport  *http.Transport
	fallback       *atomic.Bool
	connAccess     sync.Mutex
	connections    map[*httpsTrackedConn]struct{}
	closed         bool
}

func NewHTTPSTransportWrapper(dialer N.Dialer, serverAddr M.Socksaddr, fallback *atomic.Bool) *HTTPSTransportWrapper {
	wrapper := &HTTPSTransportWrapper{
		fallback:    fallback,
		connections: make(map[*httpsTrackedConn]struct{}),
	}
	dial := func(ctx context.Context, checkALPN bool) (net.Conn, error) {
		observation, _ := ctx.Value(httpsReadinessKey{}).(*httpsReadiness)
		var attempt *httpsDialAttempt
		if observation != nil && observation.beginAttempt() {
			attempt = new(httpsDialAttempt)
			ctx = context.WithValue(ctx, httpsDialAttemptKey{}, attempt)
		} else {
			observation = nil
		}
		resultConn, err := dialer.DialContext(ctx, N.NetworkTCP, serverAddr)
		if err != nil {
			if observation != nil {
				observation.completeAttempt(attempt, err, false)
			}
			return nil, err
		}
		if checkALPN {
			if tlsConn, isTLSConn := resultConn.(tls.Conn); isTLSConn {
				state := tlsConn.ConnectionState()
				if state.NegotiatedProtocol != http2.NextProtoTLS {
					tlsConn.Close()
					fallback.Store(true)
					return nil, errFallback
				}
			}
		}
		conn, err := wrapper.trackConn(resultConn)
		if observation != nil {
			observation.completeAttempt(attempt, nil, err == nil)
		}
		return conn, err
	}
	wrapper.http2Transport = &http2.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.STDConfig) (net.Conn, error) {
			return dial(ctx, true)
		},
	}
	wrapper.httpTransport = &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dial(ctx, false)
		},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx, false)
		},
	}
	return wrapper
}

func (h *HTTPSTransportWrapper) RoundTrip(request *http.Request) (*http.Response, error) {
	if h.fallback.Load() {
		return h.httpTransport.RoundTrip(request)
	}
	response, err := h.http2Transport.RoundTrip(request)
	if err != nil {
		if errors.Is(err, errFallback) {
			return h.httpTransport.RoundTrip(request)
		}
		return nil, err
	}
	return response, nil
}

func (h *HTTPSTransportWrapper) trackConn(conn net.Conn) (net.Conn, error) {
	trackedConn := &httpsTrackedConn{Conn: conn, wrapper: h}
	h.connAccess.Lock()
	if h.closed {
		h.connAccess.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	h.connections[trackedConn] = struct{}{}
	h.connAccess.Unlock()
	return trackedConn, nil
}

func (h *HTTPSTransportWrapper) Close() {
	h.connAccess.Lock()
	if h.closed {
		h.connAccess.Unlock()
		return
	}
	h.closed = true
	connections := make([]*httpsTrackedConn, 0, len(h.connections))
	for trackedConn := range h.connections {
		connections = append(connections, trackedConn)
	}
	h.connections = nil
	h.connAccess.Unlock()
	for _, trackedConn := range connections {
		trackedConn.Conn.Close()
	}
	h.http2Transport.CloseIdleConnections()
	h.httpTransport.CloseIdleConnections()
}

type httpsTrackedConn struct {
	net.Conn
	wrapper *HTTPSTransportWrapper
}

func (c *httpsTrackedConn) Close() error {
	c.wrapper.connAccess.Lock()
	delete(c.wrapper.connections, c)
	c.wrapper.connAccess.Unlock()
	return c.Conn.Close()
}

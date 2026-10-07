package urltest

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

const (
	ProtectedProbeURL     = defaultURLTestLink
	ProtectedPayloadURL   = "https://api.pokrov.space/api/public/egress-probe-64k"
	ProtectedProbeMarker  = "pokrov-authenticated-egress-v1"
	ProtectedPayloadBytes = 64 * 1024
)

// ProtectedURLTest proves the startup route with two GETs in one verified TLS
// session. The caller owns the deadline and the captured outbound identity.
func ProtectedURLTest(ctx context.Context, detour N.Dialer) (uint16, error) {
	started := time.Now()
	conn, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddr("api.pokrov.space:443"))
	if err != nil {
		return 0, &ProbeError{Stage: ProbeStageConnect, Err: err}
	}
	defer conn.Close()
	closeDone, closeStop := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closeDone)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-closeStop:
		}
	}()
	defer func() { close(closeStop); <-closeDone }()

	secured := tls.Client(conn, &tls.Config{
		ServerName: "api.pokrov.space", MinVersion: tls.VersionTLS12,
		RootCAs: adapter.RootPoolFromContext(ctx), Time: ntp.TimeFuncFromContext(ctx),
	})
	if err := secured.HandshakeContext(ctx); err != nil {
		return 0, &ProbeError{Stage: ProbeStageTLS, Err: err}
	}
	reader := bufio.NewReader(secured)
	if _, err := ProbeGET204(ctx, secured, reader, ProtectedProbeURL); err != nil {
		return 0, &ProbeError{Stage: ProbeStageResponse, Err: err}
	}
	if _, err := ProbeGET64K(ctx, secured, reader, ProtectedPayloadURL); err != nil {
		return 0, &ProbeError{Stage: ProbeStageResponse, Err: err}
	}
	if err := ctx.Err(); err != nil {
		return 0, &ProbeError{Stage: ProbeStageResponse, Err: err}
	}
	// Selected-route proof reserves zero as the unavailable delay sentinel.
	return uint16(max(1, time.Since(started)/time.Millisecond)), nil
}

// ProbeGET204 and ProbeGET64K share the candidate/startup HTTP exchange. The
// returned closed kind preserves the candidate diagnostic contract; err keeps
// the original IO/context cause for typed runtime probe errors.
func ProbeGET204(ctx context.Context, conn net.Conn, reader *bufio.Reader, endpoint string) (string, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err := request.Write(conn); err != nil {
		return "probe_failed", err
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return "probe_failed", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Pokrov-Egress-Probe") != ProtectedProbeMarker {
		return "unexpected_status", errors.New("authenticated egress response invalid")
	}
	return "", nil
}

func ProbeGET64K(ctx context.Context, conn net.Conn, reader *bufio.Reader, endpoint string) (string, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Close = true
	if err := request.Write(conn); err != nil {
		return "probe_failed", err
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return "probe_failed", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Pokrov-Egress-Probe") != ProtectedProbeMarker ||
		response.ContentLength != ProtectedPayloadBytes || response.Header.Get("Content-Encoding") != "" {
		return "unexpected_status", errors.New("authenticated egress response invalid")
	}
	if _, err := io.CopyN(io.Discard, response.Body, ProtectedPayloadBytes); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "data_stalled", ctx.Err()
		}
		return "probe_failed", err
	}
	return "", nil
}

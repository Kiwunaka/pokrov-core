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
	ProtectedProbeURL          = defaultURLTestLink
	ProtectedPayloadURL        = "https://api.pokrov.space/api/public/egress-probe-64k"
	ProtectedReserveProbeURL   = "https://pokrov.space/.well-known/pokrov/egress-probe"
	ProtectedReservePayloadURL = "https://pokrov.space/.well-known/pokrov/egress-probe-64k.bin"
	ProtectedProbeMarker       = "pokrov-authenticated-egress-v1"
	ProtectedPayloadBytes      = 64 * 1024
)

type OwnedProbeTarget struct{ Host, ProbeURL, PayloadURL string }

// ProbeOwnedTargets retains the candidate probe's primary/reserve policy inside
// the caller's deadline. A cancelled caller never opens the reserve session.
func ProbeOwnedTargets(ctx context.Context, probe func(context.Context, OwnedProbeTarget) error) error {
	primaryCtx := ctx
	cancel := func() {}
	if deadline, ok := ctx.Deadline(); ok {
		primaryCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)*3/4)
	}
	err := probe(primaryCtx, OwnedProbeTarget{"api.pokrov.space", ProtectedProbeURL, ProtectedPayloadURL})
	cancel()
	if ctx.Err() != nil {
		if err != nil {
			return err
		}
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	err = probe(ctx, OwnedProbeTarget{"pokrov.space", ProtectedReserveProbeURL, ProtectedReservePayloadURL})
	if err == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// OwnedURLTest is the light post-start liveness/endpoint check, using only the
// existing owned responders. General URLTest and latency selection do not retry.
func OwnedURLTest(ctx context.Context, detour N.Dialer) (delay uint16, err error) {
	err = ProbeOwnedTargets(ctx, func(ctx context.Context, target OwnedProbeTarget) error {
		var probeErr error
		delay, probeErr = URLTest(ctx, target.ProbeURL, detour)
		return probeErr
	})
	return
}

// ProtectedURLTest proves the startup route with two GETs in one verified TLS
// session. The caller owns the deadline and the captured outbound identity.
func ProtectedURLTest(ctx context.Context, detour N.Dialer) (uint16, error) {
	var delay uint16
	err := ProbeOwnedTargets(ctx, func(ctx context.Context, target OwnedProbeTarget) error {
		var probeErr error
		delay, probeErr = protectedURLTestAt(ctx, detour, target)
		return probeErr
	})
	return delay, err
}

func protectedURLTestAt(ctx context.Context, detour N.Dialer, target OwnedProbeTarget) (uint16, error) {
	started := time.Now()
	conn, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Host+":443"))
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
		ServerName: target.Host, MinVersion: tls.VersionTLS12,
		RootCAs: adapter.RootPoolFromContext(ctx), Time: ntp.TimeFuncFromContext(ctx),
	})
	if err := secured.HandshakeContext(ctx); err != nil {
		return 0, &ProbeError{Stage: ProbeStageTLS, Err: err}
	}
	reader := bufio.NewReader(secured)
	if _, err := ProbeGET204(ctx, secured, reader, target.ProbeURL); err != nil {
		return 0, &ProbeError{Stage: ProbeStageResponse, Err: err}
	}
	if _, err := ProbeGET64K(ctx, secured, reader, target.PayloadURL); err != nil {
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

func ProbeGET64K(ctx context.Context, conn net.Conn, reader *bufio.Reader, endpoint string, failureDetail ...*string) (string, error) {
	recordFailure := func(reason string) {
		if len(failureDetail) > 0 && failureDetail[0] != nil {
			*failureDetail[0] = reason
		}
	}
	recordFailure("")
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Close = true
	if err := request.Write(conn); err != nil {
		kind := probeIOFailureKind(err)
		if kind == "probe_failed" {
			recordFailure("write_error")
		}
		return kind, err
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		kind := probeIOFailureKind(err)
		if kind == "probe_failed" {
			recordFailure("header_error")
		}
		return kind, err
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
		if probeIOFailureKind(err) == "timeout" {
			return "data_stalled", err
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			recordFailure("body_short")
		} else {
			recordFailure("body_read_error")
		}
		return "probe_failed", err
	}
	return "", nil
}

func probeIOFailureKind(err error) string {
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	return "probe_failed"
}

package urltest

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

const (
	ProtectedProbeURL          = defaultURLTestLink
	ProtectedPayloadURL        = "https://api.pokrov.space/api/public/egress-probe-64k"
	protectedReserveProbeHost  = "birch.portal-privacy.online"
	ProtectedReserveProbeURL   = "https://" + protectedReserveProbeHost + "/.well-known/pokrov/egress-probe"
	ProtectedReservePayloadURL = "https://" + protectedReserveProbeHost + "/.well-known/pokrov/egress-probe-64k.bin"
	ProtectedProbeMarker       = "pokrov-authenticated-egress-v1"
	ProtectedPayloadBytes      = 64 * 1024
)

var (
	errOwnedProbeResponseInvalid = errors.New("authenticated egress response invalid")
	errOwnedProbeUnavailable     = errors.New("runtime egress probe unavailable")
)

type OwnedProbeTarget struct{ Host, ProbeURL, PayloadURL string }

// ProbeFailure preserves an attempted operation's cause separately from caller
// cancellation. It never retains error text, addresses, headers or payloads.
type ProbeFailure struct {
	Operation      string `json:"operation"`
	Cause          string `json:"cause"`
	Context        string `json:"cancel_state"`
	Target         string `json:"target"`
	Request        string `json:"request"`
	ElapsedMS      int64  `json:"elapsed_ms"`
	StageStartedMS int64  `json:"stage_started_ms"`
	DurationMS     int64  `json:"duration_ms"`
	Status         int    `json:"status,omitempty"`
	OSErrorCode    int    `json:"os_error_code,omitempty"`
}

func (d *ProbeFailure) Capture(ctx context.Context, operation, endpoint string, err error, status int, started time.Time) {
	if d == nil {
		return
	}
	*d = ProbeFailure{Operation: operation, Cause: "io", Context: "active", Status: status,
		ElapsedMS: time.Since(started).Milliseconds()}
	switch endpoint {
	case ProtectedProbeURL, ProtectedPayloadURL:
		d.Target = "owned_api"
	case ProtectedReserveProbeURL, ProtectedReservePayloadURL:
		d.Target = "owned_reserve"
	}
	switch endpoint {
	case ProtectedProbeURL, ProtectedReserveProbeURL:
		d.Request = "egress_204"
	case ProtectedPayloadURL, ProtectedReservePayloadURL:
		d.Request = "egress_64k"
	}
	var networkError net.Error
	var dnsError *net.DNSError
	var certificateError *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var errno syscall.Errno
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &networkError) && networkError.Timeout():
		d.Cause = "timeout"
	case errors.Is(err, context.Canceled):
		d.Cause = "cancelled"
	case errors.Is(err, io.ErrUnexpectedEOF):
		d.Cause = "unexpected_eof"
	case errors.Is(err, io.EOF):
		d.Cause = "eof"
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		d.Cause = "closed"
	case errors.As(err, &dnsError):
		d.Cause = "dns"
	case errors.As(err, &certificateError), errors.As(err, &unknownAuthority):
		d.Cause = "tls_certificate"
	case operation == "validate_response":
		d.Cause = "invalid_response"
	}
	if errors.As(err, &errno) {
		d.OSErrorCode = int(errno)
	}
	switch ctx.Err() {
	case context.DeadlineExceeded:
		d.Context = "deadline"
	case context.Canceled:
		d.Context = "cancelled"
	}
}

// HTTP64KObservation describes an attempted body read from an owned responder.
type HTTP64KObservation struct {
	Target        string `json:"target"`
	Status        int    `json:"status"`
	ReceivedBytes int64  `json:"received_bytes"`
	ExpectedBytes int64  `json:"expected_bytes"`
}

type HTTP64KDiagnostic struct {
	Failure     string
	Observation *HTTP64KObservation
	ProbeError  *ProbeFailure
}

// ProbeOwnedTargets retains the candidate probe's primary/reserve policy inside
// the caller's deadline. A cancelled caller never opens the reserve session.
func ProbeOwnedTargets(ctx context.Context, probe func(context.Context, OwnedProbeTarget) error) error {
	primaryCtx := ctx
	cancel := func() {}
	if deadline, ok := ctx.Deadline(); ok {
		primaryCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)*3/4)
	}
	primaryErr := probe(primaryCtx, OwnedProbeTarget{"api.pokrov.space", ProtectedProbeURL, ProtectedPayloadURL})
	cancel()
	if ctx.Err() != nil {
		if primaryErr != nil {
			return primaryErr
		}
		return ctx.Err()
	}
	if primaryErr == nil {
		return nil
	}
	err := probe(ctx, OwnedProbeTarget{protectedReserveProbeHost, ProtectedReserveProbeURL, ProtectedReservePayloadURL})
	if err == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	// A verified TLS reply can fail validation during a responder outage.
	// Preserve the unavailable verdict when both attempts fail.
	if ctx.Err() == nil && err != nil &&
		(errors.Is(primaryErr, errOwnedProbeResponseInvalid) || errors.Is(err, errOwnedProbeResponseInvalid)) {
		return errOwnedProbeUnavailable
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
// A non-nil stage uses zero for no active phase and ProbeStage+1 otherwise.
func ProtectedURLTest(ctx context.Context, detour N.Dialer, stage *atomic.Uint32) (uint16, error) {
	var delay uint16
	err := ProbeOwnedTargets(ctx, func(attemptCtx context.Context, target OwnedProbeTarget) error {
		var probeErr error
		delay, probeErr = protectedURLTestAt(attemptCtx, detour, target, stage, ctx)
		return probeErr
	})
	return delay, err
}

func protectedURLTestAt(ctx context.Context, detour N.Dialer, target OwnedProbeTarget, stage *atomic.Uint32, overall context.Context) (uint16, error) {
	started := time.Now()
	if stage != nil && overall.Err() == nil {
		stage.Store(uint32(ProbeStageConnect) + 1)
	}
	conn, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Host+":443"))
	if err != nil {
		if stage != nil && overall.Err() == nil {
			stage.Store(0)
		}
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
	if stage != nil {
		// Clear before this function's deferred connection cleanup begins.
		// Retain the last active stage after the overall deadline even if this
		// worker observes cancellation before the caller reads the snapshot.
		defer func() {
			if overall.Err() == nil {
				stage.Store(0)
			}
		}()
		if overall.Err() == nil {
			stage.Store(uint32(ProbeStageTLS) + 1)
		}
	}

	secured := tls.Client(conn, &tls.Config{
		ServerName: target.Host, MinVersion: tls.VersionTLS12,
		RootCAs: adapter.RootPoolFromContext(ctx), Time: ntp.TimeFuncFromContext(ctx),
	})
	if err := secured.HandshakeContext(ctx); err != nil {
		return 0, &ProbeError{Stage: ProbeStageTLS, Err: err}
	}
	if stage != nil && overall.Err() == nil {
		stage.Store(uint32(ProbeStageResponse) + 1)
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
func ProbeGET204(ctx context.Context, conn net.Conn, reader *bufio.Reader, endpoint string, detail ...*ProbeFailure) (string, error) {
	var diagnostic *ProbeFailure
	if len(detail) > 0 {
		diagnostic = detail[0]
	}
	started := time.Now()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err := request.Write(conn); err != nil {
		diagnostic.Capture(ctx, "write", endpoint, err, 0, started)
		return "probe_failed", err
	}
	started = time.Now()
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		diagnostic.Capture(ctx, "read_headers", endpoint, err, 0, started)
		return "probe_failed", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Pokrov-Egress-Probe") != ProtectedProbeMarker {
		err = errOwnedProbeResponseInvalid
		diagnostic.Capture(ctx, "validate_response", endpoint, err, response.StatusCode, started)
		// This session has failed. Closing the socket prevents Body.Close from
		// draining an invalid response until the caller's entire budget expires.
		_ = conn.Close()
		return "unexpected_status", err
	}
	return "", nil
}

func ProbeGET64K(ctx context.Context, conn net.Conn, reader *bufio.Reader, endpoint string, detail ...*HTTP64KDiagnostic) (string, error) {
	var diagnostic *HTTP64KDiagnostic
	var probeError *ProbeFailure
	if len(detail) > 0 {
		diagnostic = detail[0]
	}
	if diagnostic != nil {
		probeError = diagnostic.ProbeError
		*diagnostic = HTTP64KDiagnostic{ProbeError: probeError}
	}
	recordFailure := func(reason string) {
		if diagnostic != nil {
			diagnostic.Failure = reason
		}
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Close = true
	started := time.Now()
	if err := request.Write(conn); err != nil {
		probeError.Capture(ctx, "write", endpoint, err, 0, started)
		kind := probeIOFailureKind(err)
		if kind == "probe_failed" {
			recordFailure("write_error")
		}
		return kind, err
	}
	started = time.Now()
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		probeError.Capture(ctx, "read_headers", endpoint, err, 0, started)
		kind := probeIOFailureKind(err)
		if kind == "probe_failed" {
			recordFailure("header_error")
		}
		return kind, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Pokrov-Egress-Probe") != ProtectedProbeMarker ||
		response.ContentLength != ProtectedPayloadBytes || response.Header.Get("Content-Encoding") != "" {
		err = errOwnedProbeResponseInvalid
		probeError.Capture(ctx, "validate_response", endpoint, err, response.StatusCode, started)
		_ = conn.Close()
		return "unexpected_status", err
	}
	started = time.Now()
	if n, err := io.CopyN(io.Discard, response.Body, ProtectedPayloadBytes); err != nil {
		probeError.Capture(ctx, "read_body", endpoint, err, response.StatusCode, started)
		if diagnostic != nil {
			var target string
			switch endpoint {
			case ProtectedPayloadURL:
				target = "owned_api"
			case ProtectedReservePayloadURL:
				target = "owned_reserve"
			}
			if target != "" {
				diagnostic.Observation = &HTTP64KObservation{Target: target, Status: response.StatusCode,
					ReceivedBytes: n, ExpectedBytes: ProtectedPayloadBytes}
			}
		}
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

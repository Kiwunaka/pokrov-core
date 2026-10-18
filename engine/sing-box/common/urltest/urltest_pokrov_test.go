package urltest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/pokrov/ipinfo"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func TestHistoryStorageKeepsPublishedSnapshots(t *testing.T) {
	storage := NewHistoryStorage()
	firstInfo := &ipinfo.IpInfo{}
	first := adapter.URLTestHistory{Time: time.Unix(1, 0), Delay: 25, IpInfo: firstInfo}
	published := storage.StoreURLTestHistory("candidate", &first)
	selected := storage.LoadURLTestHistory("candidate")
	storage.StoreURLTestHistory("candidate", &adapter.URLTestHistory{Time: time.Unix(2, 0), Delay: 90})
	if selected.Delay != 25 || !selected.Time.Equal(time.Unix(1, 0)) || published.Delay != 25 {
		t.Fatal("a new probe mutated the history already held by a reader")
	}
	first.Delay = 65535
	if selected.Delay != 25 {
		t.Fatal("the producer still owns the published history storage")
	}
	current := storage.LoadURLTestHistory("candidate")
	if current.Delay != 90 || current.IpInfo != firstInfo {
		t.Fatal("a new probe lost its result or the previously known IP metadata")
	}
	secondInfo := &ipinfo.IpInfo{}
	storage.AddOnlyIpToHistory("candidate", &adapter.URLTestHistory{IpInfo: secondInfo})
	if current.IpInfo != firstInfo || storage.LoadURLTestHistory("candidate").IpInfo != secondInfo {
		t.Fatal("IP metadata refresh changed an existing reader's snapshot")
	}
	updated := make(chan struct{})
	go func() {
		defer close(updated)
		for delay := uint16(100); delay < 164; delay++ {
			first.Delay = delay
			storage.StoreURLTestHistory("candidate", &first)
		}
	}()
	for {
		if selected.Delay != 25 || storage.LoadURLTestHistory("candidate").Delay == 65535 {
			t.Fatal("a concurrent producer mutated a published result")
		}
		select {
		case <-updated:
			return
		default:
		}
	}
}

func TestProbe204PreservesSafeCauseAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(server))
		cancel()
		_ = server.Close()
	}()
	var detail ProbeFailure
	kind, err := ProbeGET204(ctx, client, bufio.NewReader(client), ProtectedProbeURL, &detail)
	if kind != "probe_failed" || !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected probe result: %s", kind)
	}
	if detail.Operation != "read_headers" || detail.Cause != "unexpected_eof" && detail.Cause != "eof" ||
		detail.Context != "cancelled" || detail.Target != "owned_api" || detail.Request != "egress_204" || detail.Status != 0 {
		t.Fatalf("lost original failure while cancelled: %+v", detail)
	}
	wrapped := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, Err: syscall.ECONNREFUSED}
	detail.Capture(ctx, "dial", ProtectedProbeURL, wrapped, 0, time.Now())
	encoded, _ := json.Marshal(detail)
	if detail.OSErrorCode != int(syscall.ECONNREFUSED) || detail.Cause != "io" || strings.Contains(string(encoded), "192.0.2") || strings.Contains(string(encoded), "https:") {
		t.Fatal("OS cause missing or raw network material retained")
	}
}

func TestProbe204RejectsInvalidStatusWithoutDrainingBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(server))
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	}()
	done := make(chan string, 1)
	var detail ProbeFailure
	go func() {
		kind, _ := ProbeGET204(context.Background(), client, bufio.NewReader(client), ProtectedProbeURL, &detail)
		done <- kind
	}()
	select {
	case kind := <-done:
		if kind != "unexpected_status" || detail.Status != 200 || detail.Operation != "validate_response" {
			t.Fatalf("wrong rejection: %s %+v", kind, detail)
		}
	case <-time.After(time.Second):
		_ = server.Close()
		<-done
		t.Fatal("invalid response waited for its body instead of preserving status")
	}
}

type localProbeDialer struct {
	N.Dialer
	dial func(context.Context) (net.Conn, error)
}

func (d localProbeDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx)
}

func TestResolveURLTestLinkUsesOwnedProbeByDefault(t *testing.T) {
	const ownedProbe = "https://api.pokrov.space/api/public/authenticated-egress-probe"
	if actual := resolveURLTestLink(""); actual != ownedProbe {
		t.Fatalf("unexpected default URL-test target: %q", actual)
	}
	const explicit = "https://example.test/probe"
	if actual := resolveURLTestLink(explicit); actual != explicit {
		t.Fatalf("explicit URL-test target changed: %q", actual)
	}
}

type probeCertificateStore struct {
	adapter.CertificateStore
	roots *x509.CertPool
}

func (s probeCertificateStore) Pool() *x509.CertPool { return s.roots }

// HYS can return the final stream bytes and EOF in the same Read. Coalesce the
// response tail to exercise that contract at the verified TLS reader boundary.
type terminalEOFProbeConn struct {
	net.Conn
	payloadStarted, terminalWithData *atomic.Bool
	tail                             *bytes.Reader
	wrapEOF                          bool
}

func (c *terminalEOFProbeConn) Read(p []byte) (n int, err error) {
	if c.tail == nil {
		n, err = c.Conn.Read(p)
		if err != nil || !c.payloadStarted.Load() {
			return
		}
		data := append([]byte(nil), p[:n]...)
		rest, readErr := io.ReadAll(c.Conn)
		if readErr != nil {
			return n, readErr
		}
		c.tail = bytes.NewReader(append(data, rest...))
	}
	n, err = c.tail.Read(p)
	if n > 0 && c.tail.Len() == 0 {
		err = io.EOF
		c.terminalWithData.Store(true)
	}
	if c.wrapEOF {
		err = qtls.WrapError(err)
	}
	return
}

func TestProtectedStartupSessionReads64KAndRetainsResponseFailures(t *testing.T) {
	localCancel := &quic.StreamError{ErrorCode: 0, Remote: false}
	if wrapped := qtls.WrapError(localCancel); errors.Unwrap(wrapped) != localCancel ||
		!errors.Is(wrapped, io.EOF) || !errors.Is(wrapped, net.ErrClosed) {
		t.Fatal("local stream cancellation lost its existing error contract")
	}
	otherError := errors.New("synthetic read failure")
	if wrapped := qtls.WrapError(otherError); errors.Unwrap(wrapped) != otherError || errors.Is(wrapped, io.EOF) {
		t.Fatal("non-EOF IO cause changed")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"api.pokrov.space", "pokrov.space"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	for _, mode := range []string{"full", "reserveFull", "reserveLiteralEOF", "reserveHysEOF", "short16k", "stall16k", "lightReserve", "lightReserveMissingMarker"} {
		t.Run(mode, func(t *testing.T) {
			eofMode := mode == "reserveLiteralEOF" || mode == "reserveHysEOF"
			var sessions, requests atomic.Int32
			var payloadWritten atomic.Int64
			var payloadStarted, terminalWithData atomic.Bool
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				method := http.MethodGet
				if strings.HasPrefix(mode, "light") {
					method = http.MethodHead
				}
				if r.Method != method || (r.Host != "api.pokrov.space" && r.Host != "pokrov.space") {
					t.Error("startup did not issue its owned GET")
				}
				if mode != "lightReserveMissingMarker" {
					w.Header().Set("X-Pokrov-Egress-Probe", ProtectedProbeMarker)
				}
				if r.URL.Path == "/api/public/authenticated-egress-probe" || r.URL.Path == "/.well-known/pokrov/egress-probe" {
					if r.Close {
						t.Error("204 closed the verified TLS session")
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if (r.URL.Path != "/api/public/egress-probe-64k" && r.URL.Path != "/.well-known/pokrov/egress-probe-64k.bin") || !r.Close {
					t.Error("startup payload request did not close its session")
				}
				w.Header().Set("Content-Length", "65536")
				payloadStarted.Store(true)
				count := ProtectedPayloadBytes
				if mode == "short16k" || mode == "stall16k" {
					count = 16 * 1024
				}
				written, _ := io.WriteString(w, strings.Repeat("p", count))
				payloadWritten.Store(int64(written))
				if mode == "stall16k" {
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					sessions.Add(1)
				}
			}
			server.StartTLS()
			defer server.Close()
			ctx := service.ContextWith[adapter.CertificateStore](context.Background(), probeCertificateStore{roots: roots})
			timeout := 2 * time.Second
			if mode == "stall16k" {
				timeout = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			dialer := ownedProbeDialer{dial: func(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
				if (strings.HasPrefix(mode, "reserve") || strings.HasPrefix(mode, "light")) && destination.Fqdn == "api.pokrov.space" {
					return nil, errors.New("primary unavailable")
				}
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
				if err == nil && eofMode {
					conn = &terminalEOFProbeConn{Conn: conn, payloadStarted: &payloadStarted,
						terminalWithData: &terminalWithData, wrapEOF: mode == "reserveHysEOF"}
				}
				return conn, err
			}}
			probe := ProtectedURLTest
			if strings.HasPrefix(mode, "light") {
				probe = OwnedURLTest
			}
			var delay uint16
			var err error
			if eofMode || mode == "stall16k" {
				var bodyKind string
				var detail HTTP64KDiagnostic
				err = ProbeOwnedTargets(ctx, func(ctx context.Context, target OwnedProbeTarget) error {
					conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Host+":443"))
					if err != nil {
						return err
					}
					defer conn.Close()
					stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
					defer stopClose()
					secured := tls.Client(conn, &tls.Config{ServerName: target.Host, RootCAs: roots, MinVersion: tls.VersionTLS12})
					if err := secured.HandshakeContext(ctx); err != nil {
						return err
					}
					reader := bufio.NewReader(secured)
					if _, err := ProbeGET204(ctx, secured, reader, target.ProbeURL); err != nil {
						return err
					}
					bodyKind, err = ProbeGET64K(ctx, secured, reader, target.PayloadURL, &detail)
					if err != nil && mode == "stall16k" {
						return &ProbeError{Stage: ProbeStageResponse, Err: err}
					}
					return err
				})
				if mode == "stall16k" {
					if bodyKind != "data_stalled" || detail.Failure != "" || detail.Observation == nil ||
						detail.Observation.Target != "owned_reserve" || detail.Observation.Status != http.StatusOK ||
						detail.Observation.ReceivedBytes != 16*1024 || detail.Observation.ExpectedBytes != ProtectedPayloadBytes {
						t.Fatalf("deadline lost partial body observation: kind=%s detail=%+v", bodyKind, detail.Observation)
					}
				} else if ctx.Err() != nil || !terminalWithData.Load() || payloadWritten.Load() != ProtectedPayloadBytes {
					t.Fatal("terminal EOF fixture did not finish its read with a live context")
				}
				if eofMode && detail.Observation != nil {
					t.Fatalf("full verified response failed at http_64k: kind=%s detail=%s target=%s status=%d received=%d/%d",
						bodyKind, detail.Failure, detail.Observation.Target, detail.Observation.Status,
						detail.Observation.ReceivedBytes, detail.Observation.ExpectedBytes)
				}
				if eofMode && (err != nil || bodyKind != "" || detail.Failure != "") {
					t.Fatal("full response did not pass the strict 65536 byte read")
				}
			} else {
				delay, err = probe(ctx, dialer)
			}
			wantSessions, wantRequests := int32(1), int32(2)
			if mode == "short16k" || mode == "stall16k" {
				wantSessions, wantRequests = 2, 4
			}
			if strings.HasPrefix(mode, "light") {
				wantRequests = 1
			}
			if sessions.Load() != wantSessions || requests.Load() != wantRequests {
				t.Fatal("GETs did not share one TLS session")
			}
			if eofMode {
				return
			}
			if mode == "full" || mode == "reserveFull" || mode == "lightReserve" {
				if err != nil || (mode != "lightReserve" && delay == 0) {
					t.Fatalf("full proof failed: %v", err)
				}
			} else {
				var failure *ProbeError
				if !errors.As(err, &failure) || failure.Stage != ProbeStageResponse || delay != 0 {
					t.Fatal("incomplete payload supplied startup proof or lost its response stage")
				}
				if mode == "stall16k" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("stall lost deadline")
				}
			}
		})
	}
}

type ownedProbeDialer struct {
	N.Dialer
	dial func(context.Context, M.Socksaddr) (net.Conn, error)
}

func (d ownedProbeDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, destination)
}

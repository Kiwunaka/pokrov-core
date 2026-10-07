package urltest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type localProbeDialer struct {
	N.Dialer
	dial func(context.Context) (net.Conn, error)
}

func (d localProbeDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx)
}

func TestURLTestCancellationAfterDialCannotSucceed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, server := net.Pipe()
	defer server.Close()
	_, err := URLTest(ctx, "http://probe.example.test/", localProbeDialer{dial: func(context.Context) (net.Conn, error) {
		cancel()
		return client, nil
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled probe supplied success instead of cancellation")
	}
}

func TestURLTestRetainsObservedTimeoutStage(t *testing.T) {
	for _, test := range []struct{ scheme, observation string }{
		{"https", "tls_timeout"},
		{"http", "response_timeout"},
	} {
		t.Run(test.observation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			client, server := net.Pipe()
			defer server.Close()
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(io.Discard, server)
				close(done)
			}()
			_, err := URLTest(ctx, test.scheme+"://probe.example.test/", localProbeDialer{dial: func(context.Context) (net.Conn, error) {
				return client, nil
			}})
			if !errors.Is(err, context.DeadlineExceeded) || ObservedFailure(err) != test.observation {
				t.Fatalf("wrong observation: %q (%T)", ObservedFailure(err), err)
			}
			if strings.Contains(err.Error(), "probe.example.test") {
				t.Fatal("probe error exposed its target")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("timed-out probe kept its connection open")
			}
		})
	}
}

func TestObservedFailureDoesNotInferTimeoutCause(t *testing.T) {
	udp := &net.OpError{Net: "udp", Op: "read", Err: context.DeadlineExceeded}
	dns := &net.DNSError{IsTimeout: true, Err: "synthetic lookup timeout"}
	if ObservedFailure(udp) != "udp_timeout" || ObservedFailure(dns) != "dns_lookup" {
		t.Fatal("typed UDP/DNS observations were lost")
	}
	for _, err := range []error{context.DeadlineExceeded, errors.New("DPI MTU ASN whitelist UDP timeout"), context.Canceled} {
		if ObservedFailure(err) != "" {
			t.Fatal("unqualified timeout acquired an inferred cause")
		}
	}
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

func TestProtectedStartupSessionReads64KAndRetainsResponseFailures(t *testing.T) {
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
	for _, mode := range []string{"full", "reserveFull", "short16k", "stall16k", "lightReserve", "lightReserveMissingMarker"} {
		t.Run(mode, func(t *testing.T) {
			var sessions, requests atomic.Int32
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
				count := ProtectedPayloadBytes
				if mode == "short16k" || mode == "stall16k" {
					count = 16 * 1024
				}
				_, _ = io.WriteString(w, strings.Repeat("p", count))
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
				if (mode == "reserveFull" || strings.HasPrefix(mode, "light")) && destination.Fqdn == "api.pokrov.space" {
					return nil, errors.New("primary unavailable")
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}}
			probe := ProtectedURLTest
			if strings.HasPrefix(mode, "light") {
				probe = OwnedURLTest
			}
			delay, err := probe(ctx, dialer)
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
			if mode == "full" || mode == "reserveFull" || mode == "lightReserve" {
				if err != nil || delay == 0 {
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

func TestOwnedProbeFallbackKeepsBudgetAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var targets []string
	err := ProbeOwnedTargets(ctx, func(probeCtx context.Context, target OwnedProbeTarget) error {
		targets = append(targets, target.Host)
		probeDeadline, _ := probeCtx.Deadline()
		if target.Host == "api.pokrov.space" {
			if remaining := time.Until(probeDeadline); remaining > 760*time.Millisecond {
				t.Fatal("primary consumed reserve budget")
			}
		} else if probeDeadline != deadline {
			t.Fatal("reserve received a new deadline")
		}
		return errors.New(target.Host)
	})
	if err == nil || len(targets) != 2 || targets[1] != "pokrov.space" {
		t.Fatal("both-failed probe supplied proof")
	}
	for _, cancelAt := range []int{1, 2} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		err = ProbeOwnedTargets(ctx, func(_ context.Context, target OwnedProbeTarget) error {
			calls++
			if calls == cancelAt {
				cancel()
				return nil // A late successful transport cannot override cancellation.
			}
			return errors.New("primary unavailable")
		})
		cancel()
		if !errors.Is(err, context.Canceled) || calls != cancelAt {
			t.Fatal("cancelled caller supplied proof or opened another target")
		}
	}
}

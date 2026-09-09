package urltest

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
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

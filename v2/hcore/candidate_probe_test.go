package hcore

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestCandidateProbeGETRequires204(t *testing.T) {
	for _, status := range []int{204, 200, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				request, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					done <- err
					return
				}
				if request.Method != "GET" || request.Host != "api.pokrov.space" || request.URL.Path != "/api/public/authenticated-egress-probe" {
					done <- fmt.Errorf("unexpected probe request")
					return
				}
				_, err = fmt.Fprintf(server, "HTTP/1.1 %d test\r\nLocation: https://example.invalid/\r\nContent-Length: 0\r\n\r\n", status)
				done <- err
			}()
			kind := candidateGET204(context.Background(), client)
			if (kind == "") != (status == 204) {
				t.Fatalf("status %d: %s", status, kind)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCandidateProbeCancellationClosesTLSAndJoins(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	dialed := make(chan struct{})
	done := make(chan string, 1)
	go func() {
		done <- candidateHTTPProbe(ctx, func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			close(dialed)
			return client, nil
		})
	}()
	<-dialed
	cancel()
	select {
	case kind := <-done:
		if kind == "" {
			t.Fatal("cancelled TLS handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled probe retained its connection")
	}
	if _, err := client.Write([]byte{0}); err == nil {
		t.Fatal("probe connection is still open")
	}
}

func TestCandidateProbeOwnsNoHostStateAndUsesProtectedTarget(t *testing.T) {
	options, tag, err := candidateOptions(libbox.BaseContext(nil), `{
		"log":{"output":"must-not-be-created.log"},
		"inbounds":[{"type":"tun","tag":"tun"}],
		"experimental":{"cache_file":{"enabled":true}},
		"outbounds":[{"type":"direct","tag":"direct"},
		 {"type":"selector","tag":"proxy","outbounds":["candidate"]},
		 {"type":"socks","tag":"candidate","server":"127.0.0.1","server_port":1}],
		"route":{"final":"direct","rules":[{"domain_suffix":["ru"],"outbound":"direct"}]},
		"_meta":{"display":"ignored"}}
	`, "physical-uplink")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "proxy" || options.Route.Final != "proxy" || options.Route.DefaultInterface != "physical-uplink" {
		t.Fatal("candidate did not retain its protected target and physical binding")
	}
	if len(options.Inbounds) != 0 || len(options.Services) != 0 || len(options.Route.Rules) != 0 || options.Experimental != nil || !options.Log.Disabled {
		t.Fatal("probe retained host-owned state")
	}
	if _, ok := options.Outbounds[1].Options.(*option.SelectorOutboundOptions); !ok {
		t.Fatal("transport material was rewritten")
	}
	result := ProbeCandidate(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, "direct-probe", time.Second, "", nil, nil)
	if result.Success || result.FailureKind != "invalid_profile" {
		t.Fatalf("direct must not prove a candidate: %+v", result)
	}
}

func TestCandidateProbePreCancelledDoesNotParseOrRetainCallback(t *testing.T) {
	var calls atomic.Int32
	result := ProbeCandidate("not a profile", "pre-cancelled", time.Second, "", nil, func() bool { calls.Add(1); return true })
	if result.Success || result.FailureKind != "cancelled" {
		t.Fatalf("pre-cancellation lost: %+v", result)
	}
	before := calls.Load()
	CancelCandidateProbe("pre-cancelled")
	time.Sleep(25 * time.Millisecond)
	if calls.Load() != before {
		t.Fatal("callback retained after return")
	}
}

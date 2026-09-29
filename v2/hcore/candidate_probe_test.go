package hcore

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestCandidateProbeGETRequires204AndMarker(t *testing.T) {
	for _, sample := range []struct {
		status int
		marker bool
	}{{204, true}, {204, false}, {200, true}, {302, true}} {
		t.Run(fmt.Sprintf("%d-marker-%t", sample.status, sample.marker), func(t *testing.T) {
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
				marker := ""
				if sample.marker {
					marker = "X-Pokrov-Egress-Probe: " + candidateProbeMarker + "\r\n"
				}
				_, err = fmt.Fprintf(server, "HTTP/1.1 %d test\r\n%sContent-Length: 0\r\n\r\n", sample.status, marker)
				done <- err
			}()
			kind := candidateGET204(context.Background(), client, candidateProbeURL)
			if (kind == "") != (sample.status == 204 && sample.marker) {
				t.Fatalf("status %d, marker %t: %s", sample.status, sample.marker, kind)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCandidateProbeGET64KReadsFullBody(t *testing.T) {
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
		if request.Method != "GET" || request.URL.Path != "/api/public/egress-probe-64k" {
			done <- fmt.Errorf("unexpected payload request")
			return
		}
		if _, err = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nX-Pokrov-Egress-Probe: %s\r\nContent-Length: %d\r\n\r\n", candidateProbeMarker, candidatePayloadBytes); err == nil {
			_, err = server.Write(make([]byte, candidatePayloadBytes))
		}
		done <- err
	}()
	if kind := candidateGET64K(context.Background(), client, candidatePayloadURL); kind != "" {
		t.Fatal(kind)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCandidateProbeGET64KShortBodyIsNotStall(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			done <- err
			return
		}
		_, err := fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nX-Pokrov-Egress-Probe: %s\r\nContent-Length: %d\r\n\r\n", candidateProbeMarker, candidatePayloadBytes)
		if err == nil {
			_, err = server.Write(make([]byte, 16*1024))
		}
		done <- err
	}()
	if kind := candidateGET64K(context.Background(), client, candidatePayloadURL); kind != "probe_failed" {
		t.Fatalf("short body: %s", kind)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCandidateProbeGET64KDetectsStallAfter16K(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			done <- err
			return
		}
		if _, err := fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nX-Pokrov-Egress-Probe: %s\r\nContent-Length: %d\r\n\r\n", candidateProbeMarker, candidatePayloadBytes); err != nil {
			done <- err
			return
		}
		_, err := server.Write(make([]byte, 16*1024))
		if err == nil {
			<-ctx.Done()
		}
		done <- err
	}()
	go func() { <-ctx.Done(); _ = client.Close() }()
	if kind := candidateGET64K(ctx, client, candidatePayloadURL); kind != "data_stalled" {
		t.Fatalf("body stall: %s", kind)
	}
	if err := <-done; err != nil && err != io.ErrClosedPipe {
		t.Fatal(err)
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
		 {"type":"selector","tag":"🌍 Страны","outbounds":["candidate"]},
		 {"type":"socks","tag":"candidate","server":"127.0.0.1","server_port":1}],
		"route":{"final":"direct","rules":[{"process_name":["discord.exe"],"outbound":"🌍 Страны"}]},
		"_meta":{"display":"ignored"}}
	`, "physical-uplink")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "🌍 Страны" || options.Route.Final != "🌍 Страны" || options.Route.DefaultInterface != "physical-uplink" {
		t.Fatal("candidate did not retain its protected target and physical binding")
	}
	if len(options.Inbounds) != 0 || len(options.Services) != 0 || len(options.Route.Rules) != 0 || options.Experimental != nil || !options.Log.Disabled {
		t.Fatal("probe retained host-owned state")
	}
	if _, ok := options.Outbounds[1].Options.(*option.SelectorOutboundOptions); !ok {
		t.Fatal("transport material was rewritten")
	}
	_, selectorTag, err := candidateOptions(libbox.BaseContext(nil), `{
		"outbounds":[{"type":"direct","tag":"direct"},
		 {"type":"selector","tag":"🌍 Страны","outbounds":["candidate"]},
		 {"type":"socks","tag":"candidate","server":"127.0.0.1","server_port":1}],
		"route":{"final":"direct"}}
	`, "physical-uplink")
	if err != nil || selectorTag != "🌍 Страны" {
		t.Fatal("candidate did not fall back to the protected selector")
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

func TestCandidateProbeStageDoesNotExposeProfile(t *testing.T) {
	const profile = `{"server":"address-private.example","password":"key-s3cr3t"}`
	stage := ""
	result := ProbeCandidate(profile, "safe-stage", time.Second, "", nil, nil,
		func(name string) { stage = name })
	if result.Success || result.FailureKind != "invalid_profile" || stage != "parse_profile" {
		t.Fatal("invalid profile did not retain its safe stage")
	}
	if strings.Contains(stage, "address-private") || strings.Contains(stage, "key-s3cr3t") {
		t.Fatal("connection material leaked into stage")
	}
}

func TestCandidateProbePreparedRussiaDNSDoesNotRequireClientRuleSets(t *testing.T) {
	// This is the shape emitted by bootstrap's _buildAndroidDnsBlock before
	// ConnectionManager probes: mode-specific DNS classification is already set.
	ctx := libbox.BaseContext(nil)
	options, _, err := candidateOptions(ctx, `{
		"dns":{"servers":[{"type":"local","tag":"bootstrap"}],"final":"bootstrap",
		 "rules":[{"domain":["candidate.invalid"],"server":"bootstrap"},
		 {"rule_set":["ru-whitelist-domains"],"server":"bootstrap"}]},
		"outbounds":[{"type":"direct","tag":"direct"},
		 {"type":"selector","tag":"proxy","outbounds":["candidate"]},
		 {"type":"socks","tag":"candidate","server":"127.0.0.1","server_port":1}],
		"route":{"final":"proxy","rule_set":[{"type":"local","format":"binary",
		 "tag":"ru-whitelist-domains","path":"client-only.srs"}]}}
	`, "")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	if len(options.DNS.Rules) != 1 || len(options.DNS.Rules[0].DefaultOptions.Domain) != 1 || options.DNS.Final != "bootstrap" {
		t.Fatal("candidate discarded the upstream resolver or kept client routing classification")
	}
}

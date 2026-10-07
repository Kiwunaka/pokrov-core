package hcore

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreconfig "github.com/Kiwunaka/POKROV-core/v2/config"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service/filemanager"
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
			kind := candidateGET204(context.Background(), client, bufio.NewReader(client), candidateProbeURL)
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
	if kind := candidateGET64K(context.Background(), client, bufio.NewReader(client), candidatePayloadURL); kind != "" {
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
	if kind := candidateGET64K(context.Background(), client, bufio.NewReader(client), candidatePayloadURL); kind != "probe_failed" {
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
	if kind := candidateGET64K(ctx, client, bufio.NewReader(client), candidatePayloadURL); kind != "data_stalled" {
		t.Fatalf("body stall: %s", kind)
	}
	if err := <-done; err != nil && err != io.ErrClosedPipe {
		t.Fatal(err)
	}
}

func TestCandidateProbeReusesVerifiedTLSSessionAndClosesEachAttempt(t *testing.T) {
	type observedRequest struct {
		path  string
		close bool
	}
	requests := make(chan observedRequest, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- observedRequest{r.URL.Path, r.Close}
		w.Header().Set("X-Pokrov-Egress-Probe", candidateProbeMarker)
		if r.URL.Path == "/probe" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(candidatePayloadBytes))
		_, _ = io.WriteString(w, strings.Repeat("p", candidatePayloadBytes))
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	target := candidateProbeTarget{"example.com", "https://example.com/probe", "https://example.com/payload"}
	dials, handshakes := 0, 0
	for attempt := 1; attempt <= 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var connection net.Conn
		kind := candidateHTTPSProbe(ctx, func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			dials++
			var err error
			connection, err = (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			return connection, err
		}, target, &tls.Config{
			ServerName: target.host,
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			VerifyConnection: func(tls.ConnectionState) error {
				handshakes++
				return nil
			},
		}, func(string) {})
		cancel()
		if kind != "" {
			t.Fatal(kind)
		}
		if dials != attempt || handshakes != attempt {
			t.Fatalf("attempt %d: dials=%d handshakes=%d", attempt, dials, handshakes)
		}
		if first, second := <-requests, <-requests; first != (observedRequest{"/probe", false}) || second != (observedRequest{"/payload", true}) {
			t.Fatalf("unexpected request session: %v %v", first, second)
		}
		if _, err := connection.Write([]byte{0}); err == nil {
			t.Fatal("completed candidate retained its connection")
		}
	}
}

func TestCandidateProbeCancellationClosesTLSAndJoins(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reading := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		var header [5]byte
		_, err := io.ReadFull(server, header[:])
		if err == nil {
			_, err = io.CopyN(io.Discard, server, int64(header[3])<<8|int64(header[4]))
		}
		serverDone <- err
	}()
	type observed struct{ kind, stage string }
	done := make(chan observed, 1)
	go func() {
		stage := ""
		kind := candidateHTTPProbe(ctx, func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			return client, nil
		}, func(name string) {
			stage = name
			if name == "tls_read" {
				close(reading)
			}
		})
		done <- observed{kind, stage}
	}()
	select {
	case <-reading:
	case result := <-done:
		t.Fatalf("TLS did not reach its response read: %s", result.kind)
	case <-time.After(time.Second):
		t.Fatal("TLS did not start its response read")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case result := <-done:
		if result.kind == "" {
			t.Fatal("cancelled TLS handshake succeeded")
		}
		if result.stage != "tls_read" {
			t.Fatalf("blocked TLS read lost its stage: %s", result.stage)
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
	if result.Success || result.FailureKind != "invalid_profile" || stage != "parse_profile" || result.Stage != stage {
		t.Fatal("invalid profile did not retain its safe stage")
	}
	if result.StageStartedMS < 0 || result.StageStartedMS > result.DurationMS {
		t.Fatal("stage start is outside the probe duration")
	}
	value := result.JSON()
	if !strings.Contains(value, `"stage":"parse_profile"`) || !strings.Contains(value, `"stage_started_ms":`) {
		t.Fatal("native result did not retain its safe stage and monotonic time")
	}
	if result.ParseDurationMS < 0 || result.CreateDurationMS != 0 || result.CertificateDurationMS != 0 ||
		result.ParseDurationMS > result.DurationMS {
		t.Fatal("invalid parse lost bounded setup timings")
	}
	for _, field := range []string{"parse_duration_ms", "create_duration_ms", "certificate_duration_ms"} {
		if !strings.Contains(value, field) {
			t.Fatal("native result lost setup timing", field)
		}
	}
	if strings.Contains(value, "address-private") || strings.Contains(value, "key-s3cr3t") {
		t.Fatal("connection material leaked into stage")
	}
	result = ProbeCandidate(`{"certificate":{"store":"unsupported-test-store"}}`,
		"create-timing", time.Second, "", nil, nil)
	if result.Success || result.Stage != "create_instance" || result.FailureKind != "invalid_profile" ||
		result.CertificateDurationMS < 0 || result.CertificateDurationMS > result.CreateDurationMS ||
		result.ParseDurationMS+result.CreateDurationMS > result.DurationMS {
		t.Fatal("constructor failure lost bounded setup timings")
	}
	certificateDuration := time.Duration(-1)
	_, err := box.New(box.Options{Context: libbox.BaseContext(nil),
		Options:                  option.Options{Certificate: &option.CertificateOptions{Store: "unsupported-test-store"}},
		CertificateStoreDuration: &certificateDuration})
	if err == nil || certificateDuration < 0 {
		t.Fatal("certificate error path did not fill its local duration")
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

func TestCandidateProbeParsesLegacyManagedDNS(t *testing.T) {
	const profile = `{
	 "log":{"disabled":true},
	 "dns":{"servers":[{"tag":"bootstrap","address":"local"},
	 {"tag":"tunnel","address":"8.8.8.8","detour":"countries"}],"final":"tunnel"},
	 "outbounds":[{"type":"selector","tag":"countries","outbounds":["candidate"]},
	 {"type":"socks","tag":"candidate","server":"192.0.2.1","server_port":1080},
	 {"type":"direct","tag":"direct"},{"type":"dns","tag":"dns-out"}],
	 "route":{"final":"countries","default_domain_resolver":{"server":"bootstrap","strategy":"prefer_ipv4"},
	 "rules":[{"protocol":"dns","outbound":"dns-out"}]},
	 "_meta":{"title":"synthetic managed profile"}}`
	optionsForStartup, err := coreconfig.ReadSingOptions(libbox.BaseContext(nil), &coreconfig.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	workingPath := t.TempDir()
	startupContext := filemanager.WithDefault(libbox.BaseContext(nil), workingPath, workingPath, os.Getuid(), os.Getgid())
	service, err := NewService(startupContext, *optionsForStartup)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := libbox.BaseContext(nil)
	options, target, err := candidateOptions(ctx, profile, "")
	if err != nil {
		t.Fatal(err)
	}
	if target != "countries" || options.DNS == nil || options.DNS.Final != "tunnel" || options.DNS.Servers[1].Type != "udp" ||
		options.DNS.Servers[1].Options.(*option.RemoteDNSServerOptions).Detour != "countries" || options.Route.DefaultDomainResolver.Server != "bootstrap" {
		t.Fatal("probe lost managed DNS, selector or bootstrap resolver")
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
}

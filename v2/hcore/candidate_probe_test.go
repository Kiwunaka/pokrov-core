package hcore

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	coreconfig "github.com/Kiwunaka/POKROV-core/v2/config"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

type candidateProbeTestOutbound struct {
	outbound.Adapter
	address string
	close   func()
}

func (p *candidateProbeTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, p.address)
}

func (*candidateProbeTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func (p *candidateProbeTestOutbound) Close() error {
	p.close()
	return nil
}

// Use a real Box and certificate store from the shipped root module graph.
// Only the outbound's wire destination and slow Close are local fixtures.
func candidateProbeFixture(t *testing.T, closeOutbound func(), failHTTP bool) (context.Context, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "candidate probe fixture"},
		DNSNames:  []string{"api.pokrov.space", "birch.portal-privacy.online"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failHTTP {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Pokrov-Egress-Probe", candidateProbeMarker)
		if strings.Contains(r.URL.Path, "64k") {
			w.Header().Set("Content-Length", fmt.Sprint(candidatePayloadBytes))
			w.Write(make([]byte, candidatePayloadBytes))
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	registry := outbound.NewRegistry()
	outbound.Register[struct{}](registry, "probe-fixture", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Outbound, error) {
		return &candidateProbeTestOutbound{outbound.NewAdapter("probe-fixture", tag, []string{"tcp"}, nil), server.Listener.Addr().String(), closeOutbound}, nil
	})
	ctx := libbox.BaseContext(nil)
	ctx = service.ContextWith[adapter.OutboundRegistry](ctx, registry)
	ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, registry)
	profile, err := json.Marshal(map[string]any{
		"certificate": map[string]any{"store": "none", "certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}},
		"outbounds":   []map[string]any{{"type": "probe-fixture", "tag": "candidate"}}, "route": map[string]any{"final": "candidate"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, string(profile)
}

func TestCandidateProbeAllowsDNSBudget(t *testing.T) {
	ctx, profile := candidateProbeFixture(t, func() {}, false)
	result := probeCandidate(ctx, profile, "dns-budget", time.Minute, "", nil, nil)
	if !result.Success || result.FailureKind != "" {
		t.Fatalf("60-second candidate probe failed: %+v", result)
	}
	result = probeCandidate(ctx, profile, "dns-budget-over-limit", time.Minute+time.Millisecond, "", nil, nil)
	if result.Success || result.FailureKind != "invalid_request" {
		t.Fatalf("candidate probe exceeded the budget limit: %+v", result)
	}
}

func TestCandidateProbeFreezesHTTPVerdictBeforeClose(t *testing.T) {
	closing, release := make(chan struct{}), make(chan struct{})
	ctx, profile := candidateProbeFixture(t, func() { close(closing); <-release }, false)
	result := make(chan CandidateProbeResult, 1)
	started := time.Now()
	go func() { result <- probeCandidate(ctx, profile, "slow-close", time.Second, "", nil, nil) }()
	select {
	case <-closing:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("probe did not complete HTTP")
	}
	// Cancellation cannot wait for an unrelated component's 10-second Close.
	cancelled := make(chan struct{})
	go func() { CancelCandidateProbe("slow-close"); close(cancelled) }()
	select {
	case <-cancelled:
	case <-time.After(250 * time.Millisecond):
		close(release)
		t.Fatal("cancellation waited for instance Close")
	}
	// The deadline also expires while Close is in flight.
	<-time.After(time.Until(started.Add(time.Second + 20*time.Millisecond)))
	close(release)
	got := <-result
	if !got.Success || got.FailureKind != "" || got.DurationMS >= 1000 {
		t.Fatalf("shutdown changed an already completed probe: %+v", got)
	}
}

func TestCandidateProbeKeepsCertificateFailureDuringClose(t *testing.T) {
	closing, release := make(chan struct{}), make(chan struct{})
	ctx, profile := candidateProbeFixture(t, func() { close(closing); <-release }, false)
	var raw map[string]any
	if err := json.Unmarshal([]byte(profile), &raw); err != nil {
		t.Fatal(err)
	}
	raw["certificate"] = map[string]any{"store": "none"}
	encoded, _ := json.Marshal(raw)
	result := make(chan CandidateProbeResult, 1)
	go func() {
		result <- probeCandidate(ctx, string(encoded), "certificate-failure", time.Second, "", nil, nil)
	}()
	select {
	case <-closing:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("certificate failure did not complete")
	}
	CancelCandidateProbe("certificate-failure")
	close(release)
	got := <-result
	if got.Success || got.FailureKind != "tls_failed" || got.ProbeError == nil || got.ProbeError.Cause != "tls_certificate" {
		t.Fatalf("cancellation erased the certificate failure: %+v", got)
	}
}

func TestCandidateProbeReportsResponderUnavailable(t *testing.T) {
	ctx, profile := candidateProbeFixture(t, func() {}, true)
	result := probeCandidate(ctx, profile, "http-unavailable", time.Second, "", nil, nil)
	if result.Success || result.FailureKind != "unavailable" || result.ProbeError == nil {
		t.Fatalf("unexpected verdict for HTTP responder failure: %+v", result)
	}
	reserve := result.ProbeError
	if reserve.Target != "owned_reserve" || reserve.Status != http.StatusServiceUnavailable ||
		reserve.PrimaryError == nil || reserve.PrimaryError.Status != http.StatusServiceUnavailable {
		t.Fatal("the unavailable verdict lost the observed responder failures")
	}
}

func TestCandidateProbeRetainsPrimaryBeforeReserveCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var failure CandidateProbeError
	calls := 0
	kind := candidateHTTPProbe(ctx, time.Now(), func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		calls++
		time.Sleep(5 * time.Millisecond)
		if calls == 1 {
			return nil, io.EOF
		}
		cancel()
		return nil, ctx.Err()
	}, func(string) {}, nil, &failure)
	result := CandidateProbeResult{FailureKind: kind, ProbeError: &failure}
	var wire map[string]any
	if err := json.Unmarshal([]byte(result.JSON()), &wire); err != nil {
		t.Fatal(err)
	}
	detail := wire["probe_error"].(map[string]any)
	primary, ok := detail["primary_error"].(map[string]any)
	if !ok || calls != 2 || primary["cause"] != "eof" || primary["target"] != "owned_api" ||
		detail["cause"] != "cancelled" || detail["target"] != "owned_reserve" {
		t.Fatalf("reserve cancellation replaced primary diagnostic: %v", detail)
	}
	if primary["duration_ms"].(float64) <= 0 || primary["duration_ms"].(float64) >= detail["duration_ms"].(float64) {
		t.Fatal("primary completion time was replaced by reserve completion")
	}
}

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
	var detail urltest.HTTP64KDiagnostic
	if kind := candidateGET64K(context.Background(), client, bufio.NewReader(client), candidatePayloadURL, &detail); kind != "" {
		t.Fatal(kind)
	}
	if detail.Failure != "" || detail.Observation != nil {
		t.Fatal("full body retained a failure observation")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCandidateProbeGET64KDetectsStallAfter16K(t *testing.T) {
	t.Run("short_body", func(t *testing.T) {
		for _, target := range []struct{ endpoint, name string }{
			{candidatePayloadURL, "owned_api"}, {urltest.ProtectedReservePayloadURL, "owned_reserve"},
		} {
			t.Run(target.name, func(t *testing.T) {
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
					done <- err
				}()
				var probeError urltest.ProbeFailure
				detail := urltest.HTTP64KDiagnostic{ProbeError: &probeError}
				result := CandidateProbeResult{Stage: "http_64k"}
				result.FailureKind = candidateGET64K(context.Background(), client, bufio.NewReader(client), target.endpoint, &detail)
				result.HTTP64KFailure, result.HTTP64KObservation = detail.Failure, detail.Observation
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				var ack map[string]any
				if err := json.Unmarshal([]byte(result.JSON()), &ack); err != nil {
					t.Fatal(err)
				}
				if result.FailureKind != "probe_failed" || ack["http_64k_failure"] != "body_short" {
					t.Fatalf("16 KiB EOF lost its closed detail: kind=%s detail=%v", result.FailureKind, ack["http_64k_failure"])
				}
				if probeError.Operation != "read_body" || probeError.Cause != "unexpected_eof" || probeError.Status != 200 || probeError.Target != target.name {
					t.Fatalf("short body lost its safe cause: %+v", probeError)
				}
				observation, ok := ack["http_64k_observation"].(map[string]any)
				if !ok || len(observation) != 4 || observation["target"] != target.name || observation["status"] != float64(200) ||
					observation["received_bytes"] != float64(16*1024) || observation["expected_bytes"] != float64(candidatePayloadBytes) {
					t.Fatalf("short body lost its actual read observation: %v", observation)
				}
			})
		}
	})
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
	var detail urltest.HTTP64KDiagnostic
	if kind := candidateGET64K(ctx, client, bufio.NewReader(client), candidatePayloadURL, &detail); kind != "data_stalled" {
		t.Fatalf("body stall: %s", kind)
	}
	// This helper retains partial reads internally. ProbeCandidate's finalizer
	// separately omits the observation from data_stalled ACKs.
	if detail.Failure != "" || detail.Observation == nil ||
		detail.Observation.Target != "owned_api" || detail.Observation.Status != 200 ||
		detail.Observation.ReceivedBytes != 16*1024 || detail.Observation.ExpectedBytes != candidatePayloadBytes {
		t.Fatal("body timeout lost its internal partial-read observation")
	}
	if err := <-done; err != nil && err != io.ErrClosedPipe {
		t.Fatal(err)
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

func TestCandidateProbeDoesNotExposeProfile(t *testing.T) {
	const profile = `{"server":"address-private.example","password":"key-s3cr3t"}`
	result := ProbeCandidate(profile, "safe-stage", time.Second, "", nil, nil)
	if result.Success || result.FailureKind != "invalid_profile" {
		t.Fatalf("invalid profile accepted: %s", result.FailureKind)
	}
	value := result.JSON()
	if strings.Contains(value, "address-private") || strings.Contains(value, "key-s3cr3t") {
		t.Fatal("connection material leaked into the probe result")
	}
	if strings.Contains(value, "http_64k_observation") {
		t.Fatal("unperformed body read acquired an observation")
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

package hcore

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	coreconfig "github.com/Kiwunaka/POKROV-core/v2/config"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
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
				var detail urltest.HTTP64KDiagnostic
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
	if detail.Failure != "" || detail.Observation != nil {
		t.Fatal("body timeout retained a generic IO observation")
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

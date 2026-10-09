package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func TestRunRejectsInvalidProfileWithoutEcho(t *testing.T) {
	path := filepath.Join(t.TempDir(), "address-private.example.json")
	if err := os.WriteFile(path, []byte(`{"outbounds":[{"type":"vless","password":"key-s3cr3t"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result := run([]string{path, "uplink-private"})
	if result.Success || result.FailureKind != "invalid_profile" {
		t.Fatalf("unexpected result: %s", result.JSON())
	}
	// Windows does not preserve Unix file modes in this test. Both stages are safe.
	if result.Stage != "parse_profile" && result.Stage != "profile_file" {
		t.Fatalf("unexpected safe failure stage: %q", result.Stage)
	}
	for _, secret := range []string{"address-private", "key-s3cr3t", "uplink-private"} {
		if strings.Contains(result.JSON(), secret) {
			t.Fatal("profile or request material leaked into result")
		}
	}
}

func TestMaterializeFixedBootstrapForHostname(t *testing.T) {
	const typedServers = `[{"type":"local","tag":"bootstrap","detour":"selector"},{"type":"udp","tag":"tunnel","server":"8.8.8.8","detour":"selector"}]`
	const profileTemplate = `{
		"log":{"disabled":true},
		"dns":{"servers":%s,"rules":[{"domain_suffix":["content.example.test"],"server":"tunnel"}],"strategy":"prefer_ipv4","independent_cache":true,"final":"tunnel"},
		"outbounds":[{"type":"vless","tag":"proxy","server":"node.example.test","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","tls":{"enabled":true,"server_name":"sni.example.test","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}},{"type":"direct","tag":"direct-runtime"%s},{"type":"selector","tag":"selector","outbounds":["proxy"]}],
		"route":{"final":"selector","rules":[{"domain_suffix":["content.example.test"],"outbound":"selector"}],"default_domain_resolver":{"server":"bootstrap","strategy":"prefer_ipv4"}}
	}`
	for _, test := range []struct {
		name          string
		servers       string
		directOptions string
	}{
		{"managed_legacy", `[{"tag":"bootstrap","address":"local"},{"tag":"tunnel","address":"8.8.8.8","detour":"selector"}]`, ""},
		{"typed", typedServers, ""},
		{"configured_direct", typedServers, `,"connect_timeout":"2s"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := []byte(fmt.Sprintf(profileTemplate, test.servers, test.directOptions))
			materialized, err := materializeFixedBootstrap(profile)
			if err != nil {
				t.Fatal(err)
			}
			var parsed option.Options
			ctx := libbox.BaseContext(nil)
			if err := parsed.UnmarshalJSONContext(ctx, materialized); err != nil {
				t.Fatalf("bootstrap profile must decode under sing-box 1.14: %v", err)
			}
			// Startup initializes DNS detours without dialing the reserved hostname.
			instance, err := box.New(box.Options{Context: ctx, Options: parsed})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			if err := instance.Start(); err != nil {
				t.Fatalf("fixed bootstrap must start under sing-box 1.14: %v", err)
			}
			var before, after map[string]any
			if err := json.Unmarshal([]byte(fmt.Sprintf(profileTemplate, typedServers, test.directOptions)), &before); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(materialized, &after); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after["outbounds"], before["outbounds"]) {
				t.Fatal("outbound connection material changed")
			}
			beforeDNS := before["dns"].(map[string]any)
			afterDNS := after["dns"].(map[string]any)
			beforeServers := beforeDNS["servers"].([]any)
			afterServers := afterDNS["servers"].([]any)
			if len(afterServers) != len(beforeServers)+1 || !reflect.DeepEqual(afterServers[:len(beforeServers)], beforeServers) {
				t.Fatal("normalized content DNS servers changed")
			}
			bootstrap := map[string]any{"type": "udp", "tag": fixedBootstrapTag, "server": "8.8.8.8"}
			if test.directOptions != "" {
				bootstrap["detour"] = "direct-runtime"
			}
			if !reflect.DeepEqual(afterServers[len(beforeServers)], bootstrap) {
				t.Fatal("fixed bootstrap DNS must use the existing IPv4 address over direct")
			}
			afterDNS["servers"] = afterServers[:len(beforeServers)]
			if !reflect.DeepEqual(afterDNS, beforeDNS) {
				t.Fatal("content DNS final, rules or policy changed")
			}
			afterRoute := after["route"].(map[string]any)
			resolver := afterRoute["default_domain_resolver"]
			if !reflect.DeepEqual(resolver, map[string]any{"server": fixedBootstrapTag, "strategy": "ipv4_only"}) {
				t.Fatal("hostname resolver must use the direct bootstrap lane")
			}
			afterRoute["default_domain_resolver"] = before["route"].(map[string]any)["default_domain_resolver"]
			if !reflect.DeepEqual(afterRoute, before["route"]) {
				t.Fatal("content routes changed")
			}
		})
	}
}

func TestMaterializeFixedBootstrapSkipsIPServer(t *testing.T) {
	profile := []byte(`{"dns":{"servers":[{"type":"udp","tag":"tunnel","server":"8.8.8.8","detour":"selector"}],"final":"tunnel"},"outbounds":[{"type":"vless","server":"192.0.2.1"}]}`)
	materialized, err := materializeFixedBootstrap(profile)
	if err != nil || string(materialized) != string(profile) {
		t.Fatal("IP-based profile should remain unchanged")
	}
}

func TestRunRejectsUnavailableBootstrapWithoutEcho(t *testing.T) {
	for _, test := range []struct {
		name   string
		server string
	}{
		{"managed_local", `{"tag":"tunnel","address":"local"}`},
		{"typed_tls", `{"type":"tls","tag":"tunnel","server":"8.8.8.8"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-profile.json")
			profile := []byte(fmt.Sprintf(`{"outbounds":[{"type":"vless","server":"private.example.test","password":"key-s3cr3t"},{"type":"direct","tag":"direct"}],"dns":{"servers":[%s],"final":"tunnel"},"route":{}}`, test.server))
			if _, err := materializeFixedBootstrap(profile); !errors.Is(err, errFixedBootstrap) {
				t.Fatal("unavailable or encrypted content DNS must not become a UDP bootstrap")
			}
			if err := os.WriteFile(path, profile, 0o600); err != nil {
				t.Fatal(err)
			}
			result := run([]string{path, "uplink-private"})
			if result.Success || result.FailureKind != "invalid_profile" {
				t.Fatalf("unexpected failure kind: %s", result.FailureKind)
			}
			if result.Stage != "bootstrap_dns" && result.Stage != "profile_file" {
				t.Fatalf("unexpected safe failure stage: %q", result.Stage)
			}
			for _, secret := range []string{"private.example.test", "key-s3cr3t", "uplink-private"} {
				if strings.Contains(result.JSON(), secret) {
					t.Fatal("profile or request material leaked into result")
				}
			}
		})
	}
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFixedProbeTimeout(t *testing.T) {
	if probeTimeout != 12*time.Second {
		t.Fatal("fixed probe must allow the 204 and 64 KiB checks within a 12-second budget")
	}
}

func TestRunRejectsInvalidRequestWithoutEcho(t *testing.T) {
	result := run([]string{"key-s3cr3t"})
	if result.Success || result.FailureKind != "invalid_request" {
		t.Fatalf("unexpected result: %s", result.JSON())
	}
	if strings.Contains(result.JSON(), "key-s3cr3t") {
		t.Fatal("request material leaked into result")
	}
}

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
	if !strings.Contains(result.JSON(), `"stage":"`+result.Stage+`"`) {
		t.Fatal("failure stage missing from JSON output")
	}
	for _, secret := range []string{"address-private", "key-s3cr3t", "uplink-private"} {
		if strings.Contains(result.JSON(), secret) {
			t.Fatal("profile or request material leaked into result")
		}
	}
}

func TestMaterializeFixedBootstrapForHostname(t *testing.T) {
	profile := []byte(`{
		"dns":{"servers":[{"tag":"bootstrap","address":"local"},{"tag":"tunnel","address":"8.8.8.8","detour":"selector"}],"final":"tunnel"},
		"outbounds":[{"type":"vless","tag":"proxy","server":"node.example.test","tls":{"server_name":"sni.example.test","reality":{"public_key":"fake-key"}}},{"type":"direct","tag":"direct"},{"type":"selector","tag":"selector","outbounds":["proxy"]}],
		"route":{"final":"selector","default_domain_resolver":{"server":"bootstrap","strategy":"prefer_ipv4"}}
	}`)
	materialized, err := materializeFixedBootstrap(profile)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	if err := json.Unmarshal(profile, &before); err != nil {
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
	if afterDNS["final"] != beforeDNS["final"] {
		t.Fatal("content DNS final changed")
	}
	beforeServers := beforeDNS["servers"].([]any)
	afterServers := afterDNS["servers"].([]any)
	if len(afterServers) != len(beforeServers)+1 || !reflect.DeepEqual(afterServers[:len(beforeServers)], beforeServers) {
		t.Fatal("content DNS servers changed")
	}
	if !reflect.DeepEqual(afterServers[len(beforeServers)], map[string]any{
		"tag": fixedBootstrapTag, "address": "8.8.8.8", "detour": "direct",
	}) {
		t.Fatal("fixed bootstrap DNS must use the existing address over direct")
	}
	resolver := after["route"].(map[string]any)["default_domain_resolver"]
	if !reflect.DeepEqual(resolver, map[string]any{"server": fixedBootstrapTag, "strategy": "ipv4_only"}) {
		t.Fatal("hostname resolver must use the direct bootstrap lane")
	}
}

func TestMaterializeFixedBootstrapSkipsIPServer(t *testing.T) {
	profile := []byte(`{"outbounds":[{"type":"vless","server":"192.0.2.1"}]}`)
	materialized, err := materializeFixedBootstrap(profile)
	if err != nil || string(materialized) != string(profile) {
		t.Fatal("IP-based profile should remain unchanged")
	}
}

func TestRunRejectsUnavailableBootstrapWithoutEcho(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-profile.json")
	profile := []byte(`{"outbounds":[{"type":"vless","server":"private.example.test","password":"key-s3cr3t"},{"type":"direct","tag":"direct"}],"dns":{"servers":[{"tag":"tunnel","address":"local"}],"final":"tunnel"},"route":{}}`)
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
}

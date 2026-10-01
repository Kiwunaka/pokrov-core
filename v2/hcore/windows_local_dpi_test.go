package hcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"testing"
	"time"
)

func TestWindowsLocalDpiPreparationRetainsVPNAndExactSignedScope(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("physical Windows admission is unavailable on this host")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("synthetic key creation failed")
	}
	now := time.Now().UTC()
	issued, expires := now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339)
	payload, _ := json.Marshal(map[string]any{
		"schema_version": "pokrov-routing-catalog-v1", "audience": "lab", "revision": 7, "security_revision": 3,
		"issued_at": issued, "expires_at": expires, "sources": []any{map[string]any{}}, "evidence": []any{},
		"services": []any{map[string]any{
			"service_id": "service-a", "enabled": true, "evidence_status": "verified", "platforms": []string{"windows"},
			"display_name": "Synthetic service", "categories": []string{"media"}, "classification": "ordinary", "reason": "Synthetic scope test",
			"source_ids": []string{"test"}, "evidence_ids": []string{"test-proof"}, "android": []any{}, "windows": []any{},
			"networks": []any{}, "provider_capability_refs": []any{}, "external_gateway_policy": "forbidden",
			"access_states": []string{"paid_unlimited"},
			"route_intents": []any{map[string]any{"mode": "selective", "action": "vpn", "local_dpi_control_host": "control.example"}},
			"domains":       []any{map[string]any{"name": "control.example", "match": "exact", "shared": false, "role": "web", "source_ids": []string{"test"}}},
		}},
	})
	digest := sha256.Sum256(payload)
	envelope, _ := json.Marshal(map[string]any{"algorithm": "Ed25519", "key_id": "test", "payload_sha256": hex.EncodeToString(digest[:]),
		"payload": json.RawMessage(payload), "signature_b64": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private,
			append([]byte("pokrov-routing-catalog-v1\n"), payload...)))})
	keys, _ := json.Marshal(map[string]string{"test": base64.StdEncoding.EncodeToString(public)})
	window := map[string]any{"service_id": "service-a", "issued_at": issued, "expires_at": expires}
	rule := map[string]any{"action": "route", "domain": []string{"control.example"}, "outbound": "group", "pokrov_catalog_window": window}
	vpnTLS := map[string]any{"enabled": true}
	vpn := map[string]any{"type": "vless", "tag": "vpn", "tls": vpnTLS}
	config := map[string]any{
		"_meta": map[string]any{"local_dpi": windowsDpiMetadata{Mode: "selective", Platform: "windows", Envelope: string(envelope),
			Digest: hex.EncodeToString(digest[:]), Revision: 7, SecurityRevision: 3, AccessState: "paid_unlimited", Services: map[string]string{"service-a": "control.example"}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, vpn,
			map[string]any{"type": "selector", "tag": "group", "outbounds": []string{"vpn"}}},
		"route": map[string]any{"final": "direct", "rules": []any{rule,
			map[string]any{"action": "route", "domain": []string{"other.example"}, "outbound": "vpn", "pokrov_catalog_window": window}}},
	}
	encoded, _ := json.Marshal(config)
	result, err := PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture")
	if err != nil {
		t.Fatal("signed Windows preparation failed")
	}
	var prepared windowsDpiPreparation
	var output struct {
		Outbounds []struct {
			Tag, Type   string
			Windows     bool   `json:"windows_direct"`
			Bind        string `json:"bind_interface"`
			VPNOutbound string `json:"vpn_outbound"`
		}
		Route struct {
			Final string
			Rules []struct{ Outbound string }
		}
	}
	if json.Unmarshal([]byte(result), &prepared) != nil || json.Unmarshal(prepared.Profile, &output) != nil ||
		len(prepared.Services) != 1 || prepared.Services[0].ControlHost != "control.example" || len(prepared.Services[0].Domains) != 1 ||
		prepared.Services[0].Domains[0].Match != "exact" || prepared.ExpiresAt != expires || len(output.Outbounds) != 4 ||
		output.Outbounds[3].Type != "pokrov-local-dpi" || !output.Outbounds[3].Windows || output.Outbounds[3].Bind != "physical-fixture" ||
		output.Outbounds[3].VPNOutbound != "group" || output.Route.Final != "direct" ||
		output.Route.Rules[0].Outbound != prepared.Services[0].OutboundTag || output.Route.Rules[1].Outbound != "vpn" {
		t.Fatal("preparation escaped signed scope or changed the existing VPN")
	}
	for _, unsafeTLS := range []any{nil, map[string]any{"enabled": true, "insecure": true}} {
		vpn["tls"] = unsafeTLS
		encoded, _ = json.Marshal(config)
		if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
			t.Fatal("plaintext or certificate-unverified VLESS fallback was prepared")
		}
	}
	vpn["tls"] = vpnTLS
	for selector, names := range map[string][]string{"domain_regex": {".*"}, "domain_keyword": {"foreign"}} {
		rule[selector] = names
		encoded, _ = json.Marshal(config)
		if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
			t.Fatal("OR domain selector expanded signed local-DPI scope")
		}
		delete(rule, selector)
	}
	window["lease_group"] = []string{"provider-fixture"}
	encoded, _ = json.Marshal(config)
	if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
		t.Fatal("provider-leased scope was prepared as local DPI")
	}
	delete(window, "lease_group")
	rule["outbound"] = "direct"
	encoded, _ = json.Marshal(config)
	if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
		t.Fatal("unprotected fallback was prepared")
	}
}

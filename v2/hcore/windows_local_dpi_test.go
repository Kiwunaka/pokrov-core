package hcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
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
			"route_intents": []any{map[string]any{"mode": "selective", "action": "vpn", "local_dpi_control_host": "control.example",
				"telegram_ws_datacenters": []any{map[string]any{"id": 2, "addresses": []string{"149.154.167.50"}, "websocket_address": "149.154.167.220"}}}},
			"domains": []any{map[string]any{"name": "control.example", "match": "exact", "shared": false, "role": "web", "source_ids": []string{"test"}}},
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
	// Same-service TG + DPI compose from the original signed metadata, through
	// one private intermediate, without replacing either existing VPN scope.
	meta := config["_meta"].(map[string]any)
	meta["telegram_ws"] = map[string]any{"schema_version": 1, "mode": "selective", "platform": "windows", "catalog_envelope": string(envelope),
		"catalog_sha256": hex.EncodeToString(digest[:]), "revision": 7, "security_revision": 3, "access_state": "paid_unlimited", "services": map[string]string{"service-a": "group"}}
	encoded, _ = json.Marshal(config)
	tgResult, err := PrepareWindowsTelegramWSProfile(string(encoded), string(keys), "lab", "physical-fixture")
	if err != nil {
		t.Fatal("TG-first preparation failed")
	}
	var tgReceipt struct {
		Profile json.RawMessage `json:"profile"`
	}
	if json.Unmarshal([]byte(tgResult), &tgReceipt) != nil {
		t.Fatal("TG private receipt invalid")
	}
	combined, err := PrepareWindowsLocalDpiProfile(string(tgReceipt.Profile), string(keys), "lab", "physical-fixture")
	var combinedReceipt windowsDpiPreparation
	var combinedProfile struct {
		Meta      json.RawMessage `json:"_meta"`
		Outbounds []struct{ Type string }
		Route     struct{ Rules []struct{ Outbound string } }
	}
	if err != nil || json.Unmarshal([]byte(combined), &combinedReceipt) != nil || json.Unmarshal(combinedReceipt.Profile, &combinedProfile) != nil || combinedProfile.Meta != nil || len(combinedProfile.Outbounds) != 5 || combinedProfile.Outbounds[3].Type != "pokrov-telegram-ws" || combinedProfile.Outbounds[4].Type != "pokrov-local-dpi" || combinedProfile.Route.Rules[0].Outbound != "pokrov-telegram-ws-service-a" || combinedProfile.Route.Rules[1].Outbound != "pokrov-local-dpi-service-a" {
		t.Fatal("TG/DPI composition lost one authority or exact TG precedence")
	}
	delete(meta, "telegram_ws")
	encoded, _ = json.Marshal(config)
	result, err := PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture")
	if err != nil {
		t.Fatal("signed Windows preparation failed")
	}
	var prepared windowsDpiPreparation
	var output struct {
		Outbounds []struct {
			Tag, Type, Detour string
			Windows           bool   `json:"windows_direct"`
			Bind              string `json:"bind_interface"`
			VPNOutbound       string `json:"vpn_outbound"`
		}
		Route struct {
			Final string
			Rules []struct {
				Outbound  string
				IPVersion int `json:"ip_version"`
			}
		}
	}
	if json.Unmarshal([]byte(result), &prepared) != nil || json.Unmarshal(prepared.Profile, &output) != nil ||
		len(prepared.Services) != 1 || prepared.Services[0].ControlHost != "control.example" || len(prepared.Services[0].Domains) != 1 ||
		prepared.Services[0].Domains[0].Match != "exact" || prepared.ExpiresAt != expires || len(output.Outbounds) != 4 ||
		output.Outbounds[3].Type != "pokrov-local-dpi" || !output.Outbounds[3].Windows || output.Outbounds[3].Bind != "physical-fixture" ||
		output.Outbounds[3].VPNOutbound != "group" || output.Route.Final != "direct" ||
		len(output.Route.Rules) != 3 || output.Route.Rules[0].Outbound != prepared.Services[0].OutboundTag ||
		output.Route.Rules[0].IPVersion != 4 || output.Route.Rules[1].Outbound != "group" ||
		output.Route.Rules[1].IPVersion != 0 || output.Route.Rules[2].Outbound != "vpn" {
		t.Fatal("preparation escaped signed scope or changed the existing VPN")
	}
	// IPv6 misses the IPv4 local override and still matches the unchanged
	// original encrypted route, rather than falling through to final direct.
	var retained struct {
		Route struct{ Rules []json.RawMessage }
	}
	if json.Unmarshal(prepared.Profile, &retained) != nil {
		t.Fatal("prepared rules invalid")
	}
	originalRule, _ := json.Marshal(rule)
	if string(retained.Route.Rules[1]) != string(originalRule) {
		t.Fatal("IPv6 fallback lost the original domain, VPN or signed window")
	}
	// Only the signed YouTube service gets a dynamic QUIC route. Its TCP
	// override remains IPv4 and the original IPv6 VPN rule stays intact.
	youtubePayload := []byte(strings.ReplaceAll(string(payload), `"service-a"`, `"youtube"`))
	youtubeDigest := sha256.Sum256(youtubePayload)
	youtubeEnvelope, _ := json.Marshal(map[string]any{"algorithm": "Ed25519", "key_id": "test",
		"payload_sha256": hex.EncodeToString(youtubeDigest[:]), "payload": json.RawMessage(youtubePayload),
		"signature_b64": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private,
			append([]byte("pokrov-routing-catalog-v1\n"), youtubePayload...)))})
	var youtubeConfig map[string]any
	_ = json.Unmarshal(encoded, &youtubeConfig)
	youtubeConfig["_meta"] = map[string]any{"local_dpi": windowsDpiMetadata{Mode: "selective", Platform: "windows",
		Envelope: string(youtubeEnvelope), Digest: hex.EncodeToString(youtubeDigest[:]), Revision: 7, SecurityRevision: 3,
		AccessState: "paid_unlimited", Services: map[string]string{"youtube": "control.example"}}}
	youtubeRules := youtubeConfig["route"].(map[string]any)["rules"].([]any)
	for _, value := range youtubeRules {
		value.(map[string]any)["pokrov_catalog_window"].(map[string]any)["service_id"] = "youtube"
	}
	checkYouTube := func(wantRules int, wantFamily int) {
		t.Helper()
		input, _ := json.Marshal(youtubeConfig)
		result, err := PrepareWindowsLocalDpiProfile(string(input), string(keys), "lab", "physical-fixture")
		var receipt windowsDpiPreparation
		var profile struct {
			Outbounds []struct {
				PreferTCP bool `json:"prefer_tcp"`
			}
			Route struct {
				Rules []struct {
					Outbound  string
					Network   string
					Port      int
					IPVersion int `json:"ip_version"`
				}
			}
		}
		if err != nil || json.Unmarshal([]byte(result), &receipt) != nil || json.Unmarshal(receipt.Profile, &profile) != nil ||
			!profile.Outbounds[3].PreferTCP || len(profile.Route.Rules) != wantRules {
			t.Fatal("YouTube preparation lost the scoped TCP preference")
		}
		if wantRules == 4 && (profile.Route.Rules[0].Network != "udp" || profile.Route.Rules[0].Port != 443 ||
			profile.Route.Rules[0].IPVersion != wantFamily || profile.Route.Rules[1].IPVersion != 4 || profile.Route.Rules[2].Outbound != "group") {
			t.Fatal("YouTube QUIC scope widened or IPv6 TCP lost its VPN route")
		}
	}
	checkYouTube(4, 0)
	youtubeRule := youtubeRules[0].(map[string]any)
	youtubeRule["ip_version"] = 4
	checkYouTube(4, 4)
	youtubeRule["network"] = "tcp"
	checkYouTube(3, 4)
	rule["ip_version"] = 6
	encoded, _ = json.Marshal(config)
	if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
		t.Fatal("IPv6-only authority was widened to physical IPv4")
	}
	delete(rule, "ip_version")
	for _, unsafeTLS := range []any{nil, map[string]any{"enabled": true, "insecure": true}} {
		vpn["tls"] = unsafeTLS
		encoded, _ = json.Marshal(config)
		if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
			t.Fatal("plaintext or certificate-unverified VLESS fallback was prepared")
		}
	}
	vpn["tls"] = vpnTLS
	// Managed Naive remains a verified TLS/H2 TCP leaf; H3/UoT and plaintext
	// cannot be promoted merely because the engine knows the naive type.
	naiveTLS := map[string]any{"enabled": true, "server_name": "proxy.example.test"}
	naive := map[string]any{"type": "naive", "tag": "vpn", "server": "192.0.2.1", "server_port": 443,
		"username": "synthetic-user", "password": "synthetic-password", "quic": false, "tls": naiveTLS}
	originalVPN := config["outbounds"].([]any)[1]
	config["outbounds"].([]any)[1] = naive
	encoded, _ = json.Marshal(config)
	if _, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err != nil {
		t.Fatal("verified Naive H2 fallback was rejected")
	}
	for field, value := range map[string]any{"tls": nil, "quic": true, "udp_over_tcp": map[string]any{"enabled": true}} {
		previous := naive[field]
		naive[field] = value
		encoded, _ = json.Marshal(config)
		if _, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil {
			t.Fatal("Naive fallback escaped the verified TLS/H2 TCP contract")
		}
		if previous == nil {
			delete(naive, field)
		} else {
			naive[field] = previous
		}
	}
	config["outbounds"].([]any)[1] = originalVPN
	// ATS wraps the ordinary VPN tag. Keep that wrapper as the fallback so its
	// lease deadlines and revocation still apply after local DPI withdrawal.
	originalOutbounds := config["outbounds"].([]any)
	lease := map[string]any{"type": "pokrov-ats-lease", "tag": "lease", "upstream_tag": "vpn"}
	bridge := map[string]any{"type": "vless", "tag": "bridge", "tls": vpnTLS}
	vpn["detour"] = "bridge"
	config["outbounds"] = append(originalOutbounds, bridge, lease)
	rule["outbound"] = "lease"
	encoded, _ = json.Marshal(config)
	result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture")
	if err != nil || json.Unmarshal([]byte(result), &prepared) != nil || json.Unmarshal(prepared.Profile, &output) != nil ||
		len(output.Outbounds) != 6 || output.Outbounds[1].Detour != "bridge" || output.Outbounds[5].VPNOutbound != "lease" {
		t.Fatal("ATS preparation rejected or bypassed the encrypted bridge and lease fallback")
	}
	vpn["detour"] = "direct"
	encoded, _ = json.Marshal(config)
	if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
		t.Fatal("an unprotected bridge detour was prepared")
	}
	vpn["detour"] = "bridge"
	bridge["detour"] = "vpn"
	encoded, _ = json.Marshal(config)
	if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
		t.Fatal("a recursive bridge detour was prepared")
	}
	delete(bridge, "detour")
	lease["upstream_tag"] = "direct"
	encoded, _ = json.Marshal(config)
	if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
		t.Fatal("ATS wrapper admitted an unprotected upstream")
	}
	config["outbounds"] = originalOutbounds
	delete(vpn, "detour")
	rule["outbound"] = "group"
	// A fixed flowless VLESS backend may replace TLS only when its exact
	// detour supplies the pinned Noise transport. Retain the ordinary group.
	delete(vpn, "tls")
	vpn["server"], vpn["server_port"], vpn["network"] = "127.0.0.1", 12543, "tcp"
	vpn["uuid"], vpn["detour"] = "00000000-0000-4000-8000-000000000001", "dns-tunnel"
	carrier := map[string]any{"type": "dnstt", "tag": "dns-tunnel", "domain": "t.example.test",
		"publicKey": strings.Repeat("01", 32), "resolvers": []string{"192.0.2.1:53"}, "network": "tcp", "tunnel_per_resolver": 1}
	config["outbounds"] = append(originalOutbounds, carrier)
	encoded, _ = json.Marshal(config)
	if _, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err != nil {
		t.Fatal("fixed VLESS/Noise fallback was rejected")
	}
	vpn["server_port"] = 443
	encoded, _ = json.Marshal(config)
	if _, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil {
		t.Fatal("Noise exception widened to an arbitrary plaintext VLESS server")
	}
	config["outbounds"] = originalOutbounds
	for _, field := range []string{"server", "server_port", "network", "uuid", "detour"} {
		delete(vpn, field)
	}
	vpn["tls"] = vpnTLS
	for selector, value := range map[string]any{"domain_regex": []string{".*"}, "domain_keyword": []string{"foreign"}, "ip_cidr": []string{"0.0.0.0/0"}, "invert": true} {
		rule[selector] = value
		encoded, _ = json.Marshal(config)
		if result, err = PrepareWindowsLocalDpiProfile(string(encoded), string(keys), "lab", "physical-fixture"); err == nil || result != "" {
			t.Fatal("OR address selector expanded signed local-DPI scope")
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

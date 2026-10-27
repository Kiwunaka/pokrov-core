package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/pokrov/telegramws"
)

func TestTelegramWSPreparationRequiresSignedScopeAndKeepsStaticFallbackRule(t *testing.T) {
	payload := strings.Replace(localDpiVerifierPayload(time.Now()), `"platforms":["android"]`, `"platforms":["windows"]`, 1)
	table := `"telegram_ws_datacenters":[{"id":2,"addresses":["149.154.167.50"],"websocket_address":"149.154.167.220"}],`
	payload = strings.Replace(payload, `"local_dpi_control_host":`, table+`"local_dpi_control_host":`, 1)
	envelope, keys, digest := localDpiSignedCatalog(payload)
	var signed struct {
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
	}
	_ = json.Unmarshal([]byte(payload), &signed)
	metadata := telegramMetadata{SchemaVersion: 1, Mode: "selective", Platform: "windows", Envelope: envelope, Digest: digest,
		Revision: 7, SecurityRevision: 3, AccessState: "trial_premium", Services: map[string]string{"service-a": "vpn"}}
	config := map[string]any{
		"_meta":     map[string]any{"telegram_ws": metadata, "retained": true},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "vless", "tag": "vpn", "tls": map[string]any{"enabled": true}}},
		"route": map[string]any{"final": "direct", "rules": []any{
			map[string]any{"action": "route", "process_name": []string{"explicit-vpn.exe"}, "outbound": "vpn"},
			map[string]any{"action": "route", "domain": []string{"control.example"}, "outbound": "vpn", "pokrov_catalog_window": map[string]any{"service_id": "service-a", "issued_at": signed.IssuedAt, "expires_at": signed.ExpiresAt}},
			map[string]any{"action": "route", "network": "tcp", "port": 443, "outbound": "direct"},
		}},
	}
	encoded, _ := json.Marshal(config)
	result, err := PrepareTelegramWSProfile(string(encoded), keys, "lab", "physical-fixture", "windows")
	if err != nil {
		t.Fatal("signed TG preparation failed")
	}
	var receipt telegramPreparation
	var prepared map[string]json.RawMessage
	if json.Unmarshal([]byte(result), &receipt) != nil || receipt.SchemaVersion != 1 || len(receipt.Services) != 1 || receipt.ExpiresAt != signed.ExpiresAt || json.Unmarshal(receipt.Profile, &prepared) != nil || prepared["_meta"] == nil {
		t.Fatal("private signed receipt or original metadata missing")
	}
	var route map[string]json.RawMessage
	var rules []map[string]json.RawMessage
	_ = json.Unmarshal(prepared["route"], &route)
	_ = json.Unmarshal(route["rules"], &rules)
	if len(rules) != 4 || string(rules[0]["outbound"]) != `"vpn"` || rules[0]["process_name"] == nil || string(rules[1]["outbound"]) != `"pokrov-telegram-ws-service-a"` || rules[1]["pokrov_catalog_window"] != nil || string(rules[1]["ip_cidr"]) != `["149.154.167.50/32"]` {
		t.Fatal("exact TG rule could expire or lose precedence to Direct")
	}
	delete(prepared, "_meta")
	runtimeBytes, _ := json.Marshal(prepared)
	ctx := include.Context(context.Background())
	options, err := parseConfig(ctx, string(runtimeBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := telegramws.BindPreparations(ctx, options); err != nil {
		t.Fatal("native proof did not bind current fallback graph")
	}
	if _, err := PrepareTelegramWSProfile(string(receipt.Profile), keys, "lab", "physical-fixture", "windows"); err == nil {
		t.Fatal("preexisting TG fields bypassed original signed preparation")
	}
	originalOutbounds := config["outbounds"]
	config["outbounds"] = []any{
		map[string]any{"type": "direct", "tag": "direct"},
		map[string]any{"type": "vless", "tag": "vpn", "server": "127.0.0.1", "server_port": 12543,
			"uuid": "00000000-0000-4000-8000-000000000001", "network": "tcp", "detour": "dns-tunnel"},
		map[string]any{"type": "dnstt", "tag": "dns-tunnel", "domain": "t.example.test",
			"publicKey": strings.Repeat("01", 32), "resolvers": []string{"192.0.2.1:53"}, "network": "tcp"},
	}
	encoded, _ = json.Marshal(config)
	result, err = PrepareTelegramWSProfile(string(encoded), keys, "lab", "physical-fixture", "windows")
	if err != nil || json.Unmarshal([]byte(result), &receipt) != nil || json.Unmarshal(receipt.Profile, &prepared) != nil {
		t.Fatal("signed TG preparation rejected the fixed Noise fallback")
	}
	delete(prepared, "_meta")
	runtimeBytes, _ = json.Marshal(prepared)
	options, err = parseConfig(ctx, string(runtimeBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = telegramws.BindPreparations(ctx, options); err != nil {
		t.Fatal("TG preparation did not bind the Noise carrier")
	}
	options.Outbounds[2].Options.(*option.DnsttOptions).PublicKey = strings.Repeat("02", 32)
	if _, err = telegramws.BindPreparations(ctx, options); err == nil {
		t.Fatal("changing the Noise pin bypassed one-use TG graph authority")
	}
	config["outbounds"] = originalOutbounds
	config["outbounds"] = []any{
		map[string]any{"type": "direct", "tag": "direct"},
		map[string]any{"type": "naive", "tag": "vpn", "server": "192.0.2.1", "server_port": 443,
			"username": "synthetic-user", "password": "synthetic-password", "quic": false,
			"tls": map[string]any{"enabled": true, "server_name": "proxy.example.test"}},
	}
	encoded, _ = json.Marshal(config)
	result, err = PrepareTelegramWSProfile(string(encoded), keys, "lab", "physical-fixture", "windows")
	if err != nil || json.Unmarshal([]byte(result), &receipt) != nil || json.Unmarshal(receipt.Profile, &prepared) != nil {
		t.Fatal("signed TG preparation rejected verified Naive H2")
	}
	delete(prepared, "_meta")
	runtimeBytes, _ = json.Marshal(prepared)
	options, err = parseConfig(ctx, string(runtimeBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = telegramws.BindPreparations(ctx, options); err != nil {
		t.Fatal("TG preparation did not bind the Naive H2 fallback")
	}
	options.Outbounds[1].Options.(*option.NaiveOutboundOptions).Password = "changed-synthetic-password"
	if _, err = telegramws.BindPreparations(ctx, options); err == nil {
		t.Fatal("changing Naive credentials bypassed one-use TG graph authority")
	}
	config["outbounds"] = originalOutbounds
	for _, invalid := range []string{"10.0.0.1", "2001:b28:f23d:f001::a%owned"} {
		changed := strings.Replace(payload, "149.154.167.50", invalid, 1)
		metadata.Envelope, keys, metadata.Digest = localDpiSignedCatalog(changed)
		config["_meta"] = map[string]any{"telegram_ws": metadata}
		encoded, _ = json.Marshal(config)
		if _, err := PrepareTelegramWSProfile(string(encoded), keys, "lab", "physical-fixture", "windows"); err == nil {
			t.Fatal("signed private/scoped DC literal admitted")
		}
	}
}

const localDpiVerifierPayloadTemplate = `{"audience":"lab","evidence":[{"evidence_id":"evidence-a","expires_at":"EXPIRES","observed_at":"ISSUED","origin":"synthetic","service_id":"service-a","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","source_ids":["source-a"]}],"expires_at":"EXPIRES","issued_at":"ISSUED","revision":7,"schema_version":"pokrov-routing-catalog-v1","security_revision":3,"services":[{"access_states":["trial_premium"],"android":[],"categories":["video"],"classification":"ordinary","display_name":"\u041f\u043e\u043a\u0440\u043e\u0432","domains":[{"match":"exact","name":"control.example","role":"web","shared":false,"source_ids":["source-a"]}],"enabled":true,"evidence_ids":["evidence-a"],"evidence_status":"verified","external_gateway_policy":"forbidden","networks":[],"platforms":["android"],"provider_capability_refs":[],"reason":"synthetic test","route_intents":[{"action":"vpn","local_dpi_control_host":"control.example","mode":"selective"}],"service_id":"service-a","source_ids":["source-a"],"windows":[]}],"sources":[{"expires_at":"EXPIRES","license":"test","retrieved_at":"ISSUED","revision":"test-1","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","source_id":"source-a","url":"https://source.invalid/catalog"}]}`

func localDpiVerifierPayload(now time.Time) string {
	payload := strings.ReplaceAll(localDpiVerifierPayloadTemplate, "ISSUED", now.Add(-time.Hour).UTC().Format(time.RFC3339))
	return strings.ReplaceAll(payload, "EXPIRES", now.Add(time.Hour).UTC().Format(time.RFC3339))
}

func localDpiSignedCatalog(payload string) (envelope, keys, digest string) {
	// This deterministic key exists only in synthetic unit fixtures.
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	sum := sha256.Sum256([]byte(payload))
	digest = hex.EncodeToString(sum[:])
	signature := ed25519.Sign(private, append([]byte("pokrov-routing-catalog-v1\n"), []byte(payload)...))
	envelope = fmt.Sprintf(`{"algorithm":"Ed25519","key_id":"test-key","payload_sha256":"%s","payload":%s,"signature_b64":"%s"}`,
		digest, payload, base64.RawURLEncoding.EncodeToString(signature))
	keys = fmt.Sprintf(`{"test-key":"%s"}`, base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)))
	return
}

func TestLocalDpiCatalogRejectsCryptoAndCallerFenceMismatch(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	payload := localDpiVerifierPayload(now)
	envelope, keys, digest := localDpiSignedCatalog(payload)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6b}, ed25519.SeedSize))
	wrongKeys := fmt.Sprintf(`{"test-key":"%s"}`, base64.StdEncoding.EncodeToString(other.Public().(ed25519.PublicKey)))
	var object map[string]json.RawMessage
	_ = json.Unmarshal([]byte(envelope), &object)
	var signature string
	_ = json.Unmarshal(object["signature_b64"], &signature)
	badSignature := strings.Replace(envelope, signature, base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)), 1)
	cases := []struct {
		name, envelope, keys, audience, digest string
		revision, securityRevision             int64
		now                                    time.Time
	}{
		{"tamper", strings.Replace(envelope, `\u041f`, `\u0420`, 1), keys, "lab", digest, 7, 3, now},
		{"signature", badSignature, keys, "lab", digest, 7, 3, now},
		{"pinned key", envelope, wrongKeys, "lab", digest, 7, 3, now},
		{"digest", envelope, keys, "lab", strings.Repeat("0", 64), 7, 3, now},
		{"revision", envelope, keys, "lab", digest, 8, 3, now},
		{"security revision", envelope, keys, "lab", digest, 7, 4, now},
		{"audience", envelope, keys, "production", digest, 7, 3, now},
		{"not issued", envelope, keys, "lab", digest, 7, 3, now.Add(-time.Hour - time.Second)},
		{"expired", envelope, keys, "lab", digest, 7, 3, now.Add(time.Hour)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if verifyLocalDpiCatalog(test.envelope, test.keys, test.audience, test.digest,
				test.revision, test.securityRevision, "service-a", "control.example", "trial_premium", test.now) {
				t.Fatal("catalog accepted mismatched signature or native fence")
			}
		})
	}
}

func TestLocalDpiCatalogModeBindsSignedYouTubeIntent(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var payload map[string]any
	if err := json.Unmarshal([]byte(localDpiVerifierPayload(now)), &payload); err != nil {
		t.Fatal(err)
	}
	service := payload["services"].([]any)[0].(map[string]any)
	service["service_id"] = "youtube"
	service["domains"] = append(service["domains"].([]any), map[string]any{
		"name": "smart.example", "match": "exact", "role": "web", "shared": false, "source_ids": []string{"source-a"},
	})
	selective := map[string]any{"mode": "selective", "action": "vpn", "local_dpi_control_host": "control.example"}
	smart := map[string]any{"mode": "smart_safe", "action": "vpn", "local_dpi_control_host": "smart.example"}
	service["route_intents"] = []any{selective, smart}
	verify := func(serviceID, host, mode string) bool {
		encoded, _ := json.Marshal(payload)
		envelope, keys, digest := localDpiSignedCatalog(string(encoded))
		return verifyLocalDpiCatalogPlatform(envelope, keys, "lab", digest, 7, 3,
			serviceID, host, "trial_premium", "android", mode, now)
	}
	if !verify("youtube", "smart.example", "smart_safe") || !verify("youtube", "control.example", "selective") {
		t.Fatal("signed mode-specific YouTube control hosts were rejected")
	}
	encoded, _ := json.Marshal(payload)
	envelope, keys, digest := localDpiSignedCatalog(string(encoded))
	if !verifyLocalDpiCatalog(envelope, keys, "lab", digest, 7, 3, "youtube", "control.example", "trial_premium", now) {
		t.Fatal("legacy Selective verifier rejected its signed scope")
	}
	if verify("youtube", "control.example", "smart_safe") || verify("youtube", "smart.example", "selective") ||
		verify("youtube", "smart.example", "full") {
		t.Fatal("admission escaped its signed mode and host")
	}
	smart["action"] = "direct"
	if verify("youtube", "smart.example", "smart_safe") {
		t.Fatal("Smart Safe admitted a non-VPN intent")
	}
	smart["action"] = "vpn"
	service["service_id"] = "other"
	if verify("other", "smart.example", "smart_safe") {
		t.Fatal("Smart Safe admitted a service other than YouTube")
	}
}

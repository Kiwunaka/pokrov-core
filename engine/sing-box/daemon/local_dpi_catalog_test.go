package daemon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

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

func localDpiVerifyTest(envelope, keys, digest string, now time.Time) bool {
	return verifyLocalDpiCatalog(envelope, keys, "lab", digest, 7, 3, "service-a", "control.example", "trial_premium", now)
}

func TestLocalDpiCatalogVerifiesOriginalUnicodePayload(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := localDpiVerifierPayload(now)
	envelope, keys, digest := localDpiSignedCatalog(payload)
	if !VerifyLocalDpiCatalog(envelope, keys, "lab", digest, 7, 3, "service-a", "control.example", "trial_premium") {
		t.Fatal("current signed Unicode payload was rejected")
	}
	var decoded any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatal("synthetic payload is invalid")
	}
	remarshaled, err := json.Marshal(decoded)
	if err != nil || bytes.Equal(remarshaled, []byte(payload)) {
		t.Fatal("fixture did not distinguish Python ensure_ascii bytes")
	}
	if localDpiVerifyTest(strings.Replace(envelope, payload, string(remarshaled), 1), keys, digest, now) {
		t.Fatal("re-serialized payload reused original signature")
	}
	// Other ordinary intents do not confer localDPI authority, but do not
	// invalidate the selective VPN row with its signed control-host hint.
	ordinary := strings.Replace(payload, `"route_intents":[`, `"route_intents":[{"action":"vpn","mode":"full"},`, 1)
	envelope, keys, digest = localDpiSignedCatalog(ordinary)
	if !localDpiVerifyTest(envelope, keys, digest, now) {
		t.Fatal("ordinary catalog intent changed explicit localDPI projection")
	}
}

func TestLocalDpiCatalogRequiresSignedControlHostForOffload(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	legacy := strings.Replace(localDpiVerifierPayload(now), `"local_dpi_control_host":"control.example",`, "", 1)
	envelope, keys, digest := localDpiSignedCatalog(legacy)
	if localDpiVerifyTest(envelope, keys, digest, now) {
		t.Fatal("ordinary selective VPN intent authorized localDPI")
	}
	full := strings.Replace(legacy, `"mode":"selective"`, `"mode":"full"`, 1)
	envelope, keys, digest = localDpiSignedCatalog(full)
	if localDpiVerifyTest(envelope, keys, digest, now) {
		t.Fatal("ordinary Full VPN intent authorized localDPI")
	}
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

func TestLocalDpiCatalogRejectsWrongSelectiveHostProjection(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	payload := localDpiVerifierPayload(now)
	cases := []struct{ name, from, to string }{
		{"service", `"service_id":"service-a","source_ids"`, `"service_id":"other","source_ids"`},
		{"control hint", `"local_dpi_control_host":"control.example"`, `"local_dpi_control_host":"other.example"`},
		{"host absent", `"name":"control.example"`, `"name":"other.example"`},
		{"shared", `"shared":false`, `"shared":true`},
		{"suffix", `"match":"exact"`, `"match":"suffix"`},
		{"full", `"mode":"selective"`, `"mode":"full"`},
		{"direct", `"action":"vpn"`, `"action":"direct"`},
		{"gateway", `"action":"vpn"`, `"action":"approved_gateway"`},
		{"disabled", `"enabled":true`, `"enabled":false`},
		{"unverified", `"evidence_status":"verified"`, `"evidence_status":"source_only"`},
		{"platform", `"platforms":["android"]`, `"platforms":["windows"]`},
		{"access", `"access_states":["trial_premium"]`, `"access_states":["paid_unlimited"]`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			changed := strings.Replace(payload, test.from, test.to, 1)
			envelope, keys, digest := localDpiSignedCatalog(changed)
			if localDpiVerifyTest(envelope, keys, digest, now) {
				t.Fatal("signed catalog authorized wrong service/host/scope")
			}
		})
	}
	envelope, keys, digest := localDpiSignedCatalog(payload)
	if verifyLocalDpiCatalog(envelope, keys, "lab", digest, 7, 3, "service-a", "Control.example", "trial_premium", now) {
		t.Fatal("noncanonical native hostname supplied authority")
	}
}

func TestLocalDpiCatalogRejectsDuplicateConsumedFieldsAndIdentities(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	payload := localDpiVerifierPayload(now)
	var object map[string]json.RawMessage
	_ = json.Unmarshal([]byte(payload), &object)
	var services, domains []json.RawMessage
	_ = json.Unmarshal(object["services"], &services)
	var selected map[string]json.RawMessage
	_ = json.Unmarshal(services[0], &selected)
	_ = json.Unmarshal(selected["domains"], &domains)
	cases := []struct{ name, payload string }{
		{"payload field", strings.Replace(payload, `"revision":7`, `"revision":7,"revision":7`, 1)},
		{"service field", strings.Replace(payload, `"enabled":true`, `"enabled":true,"enabled":true`, 1)},
		{"domain field", strings.Replace(payload, `"shared":false`, `"shared":false,"shared":false`, 1)},
		{"service ID", strings.Replace(payload, string(object["services"]), "["+string(services[0])+","+string(services[0])+"]", 1)},
		{"intent mode", strings.Replace(payload, `"route_intents":[`, `"route_intents":[{"action":"vpn","mode":"selective"},`, 1)},
		{"domain identity", strings.Replace(payload, string(selected["domains"]), "["+string(domains[0])+","+string(domains[0])+"]", 1)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			envelope, keys, digest := localDpiSignedCatalog(test.payload)
			if localDpiVerifyTest(envelope, keys, digest, now) {
				t.Fatal("duplicate signed field or identity supplied authority")
			}
		})
	}
	envelope, keys, digest := localDpiSignedCatalog(payload)
	if localDpiVerifyTest(strings.Replace(envelope, `"algorithm":"Ed25519"`, `"algorithm":"Ed25519","algorithm":"Ed25519"`, 1), keys, digest, now) {
		t.Fatal("duplicate envelope field supplied authority")
	}
	duplicateKeys := strings.TrimSuffix(keys, "}") + "," + strings.TrimPrefix(keys, "{")
	if localDpiVerifyTest(envelope, duplicateKeys, digest, now) {
		t.Fatal("duplicate native key ID supplied authority")
	}
}

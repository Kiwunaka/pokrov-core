package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Match the App's firstProviderQaRuntimeConfig and the shared backend runtime
// response. This only parses/verifies synthetic bytes; it starts no worker.
func TestFirstProviderQARuntimeControlBoundary(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	qaCapability := "saqa1.c3ludGhldGlj." + strings.Repeat("a", 64)
	standardCapability := "pkr_src1.c3ludGhldGlj." + strings.Repeat("b", 64)
	profile := strings.Repeat("c", 64)
	nonce := strings.Repeat("d", 32)
	config := map[string]any{
		"schema_version": "pokrov-smart-access-runtime-worker-v1", "profile_digest": profile,
		"catalog_sha256": strings.Repeat("e", 64), "platform": "windows", "audience": "production",
		"api_base_url": "https://qa.pokrov.test", "dns_resolver": "dns-direct", "capability": qaCapability,
		"issued_at": now.Format(time.RFC3339), "expires_at": now.Add(5 * time.Minute).Format(time.RFC3339),
		"lease_keys_by_id": map[string]string{"owned-smart-dns-lease-v1": base64.StdEncoding.EncodeToString(publicKey)},
	}
	parse := func() (*smartAccessRuntimeControlWorker, error) {
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		return parseSmartAccessRuntimeControl(string(raw), now)
	}
	worker, err := parse()
	if err != nil {
		t.Fatal("Core rejected the App-shaped Windows QA control config:", err)
	}
	if smartAccessRuntimeCapability.MatchString(qaCapability) {
		t.Fatal("QA capability was reclassified as ordinary authority")
	}
	response := func(capability, platform, action, reason string) []byte {
		binding := sha256.Sum256([]byte("pokrov-smart-access-runtime-binding-v1\x00" + nonce + "\x00" + capability))
		payload := map[string]string{
			"schema_version": "pokrov-smart-access-runtime-control-v1", "request_nonce": nonce,
			"device_binding": hex.EncodeToString(binding[:]), "profile_digest": profile,
			"platform": platform, "audience": "production", "action": action, "reason": reason,
			"issued_at": now.Format(time.RFC3339), "expires_at": now.Add(time.Minute).Format(time.RFC3339),
		}
		canonical, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(canonical)
		signature := ed25519.Sign(privateKey, append([]byte("pokrov-smart-access-runtime-control-v1\n"), canonical...))
		raw, err := json.Marshal(map[string]any{"schema": "smart-access-runtime-control-response-v1",
			"envelope": map[string]any{"algorithm": "Ed25519", "key_id": "owned-smart-dns-lease-v1",
				"payload": payload, "payload_sha256": hex.EncodeToString(digest[:]),
				"signature_b64": base64.RawURLEncoding.EncodeToString(signature)}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	current := response(qaCapability, "windows", "none", "current")
	if reason, _, ok := worker.verify(current, nonce, now, now); !ok || reason != "current" {
		t.Fatal("valid signed QA control was rejected")
	}
	if reason, _, ok := worker.verify(response(qaCapability, "windows", "terminate", "access_denied"), nonce, now, now); !ok || reason != "access_denied" {
		t.Fatal("signed QA denial was rejected")
	}
	if _, _, ok := worker.verify(response(standardCapability, "windows", "none", "current"), nonce, now, now); ok {
		t.Fatal("ordinary capability binding authorized the QA worker")
	}
	if _, _, ok := worker.verify(current, nonce, now, now.Add(2*time.Minute)); ok {
		t.Fatal("expired QA control was accepted")
	}
	config["platform"] = "android"
	if _, err = parse(); err == nil {
		t.Fatal("Windows-only QA capability admitted Android")
	}
	config["capability"] = standardCapability
	ordinary, err := parse()
	if err != nil {
		t.Fatal("ordinary Android runtime control changed:", err)
	}
	if _, _, ok := ordinary.verify(response(standardCapability, "android", "none", "current"), nonce, now, now); !ok {
		t.Fatal("ordinary signed runtime control changed")
	}
}

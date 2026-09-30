package daemon

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"time"
)

// VerifyLocalDpiCatalog checks the pinned signature and the Android selective
// control-host projection. Native callers own identity/proof and runtime fences;
// this is neither a full catalog compiler nor an admission mutation.
func VerifyLocalDpiCatalog(envelopeJSON, publicKeysJSON, audience, expectedPayloadSHA256 string,
	expectedRevision, expectedSecurityRevision int64, serviceID, controlHost, accessState string) bool {
	return verifyLocalDpiCatalog(envelopeJSON, publicKeysJSON, audience, expectedPayloadSHA256,
		expectedRevision, expectedSecurityRevision, serviceID, controlHost, accessState, time.Now())
}

func verifyLocalDpiCatalog(envelopeJSON, publicKeysJSON, audience, expectedPayloadSHA256 string,
	expectedRevision, expectedSecurityRevision int64, serviceID, controlHost, accessState string, now time.Time) bool {
	if len(envelopeJSON) > 1<<20 || (audience != "lab" && audience != "production") ||
		!smartAccessRuntimeDigest.MatchString(expectedPayloadSHA256) ||
		expectedRevision < 1 || expectedRevision > 9007199254740991 ||
		expectedSecurityRevision < 1 || expectedSecurityRevision > 9007199254740991 ||
		!routingCatalogServiceID.MatchString(serviceID) || !localDpiCatalogHost(controlHost) {
		return false
	}
	switch accessState {
	case "trial_premium", "bonus_premium", "paid_unlimited", "free_monthly", "free_soft_mode":
	default:
		return false
	}
	envelope, ok := smartAccessControlObject([]byte(envelopeJSON), "algorithm", "key_id", "payload_sha256", "payload", "signature_b64")
	if !ok {
		return false
	}
	algorithm, _ := localDpiCatalogString(envelope["algorithm"])
	keyID, _ := localDpiCatalogString(envelope["key_id"])
	digest, _ := localDpiCatalogString(envelope["payload_sha256"])
	signatureText, _ := localDpiCatalogString(envelope["signature_b64"])
	if algorithm != "Ed25519" || !routingCatalogServiceID.MatchString(keyID) ||
		digest != expectedPayloadSHA256 || len(signatureText) != 86 {
		return false
	}
	key, ok := localDpiCatalogPinnedKey(publicKeysJSON, keyID)
	if !ok {
		return false
	}
	rawPayload := envelope["payload"]
	sum := sha256.Sum256(rawPayload)
	if hex.EncodeToString(sum[:]) != digest {
		return false
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureText)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key, append([]byte("pokrov-routing-catalog-v1\n"), rawPayload...), signature) {
		return false
	}
	payload, ok := smartAccessControlObject(rawPayload, "schema_version", "revision", "security_revision", "audience",
		"issued_at", "expires_at", "sources", "evidence", "services")
	if !ok {
		return false
	}
	schema, _ := localDpiCatalogString(payload["schema_version"])
	signedAudience, _ := localDpiCatalogString(payload["audience"])
	var revision, securityRevision int64
	if schema != "pokrov-routing-catalog-v1" || signedAudience != audience ||
		json.Unmarshal(payload["revision"], &revision) != nil || revision != expectedRevision ||
		json.Unmarshal(payload["security_revision"], &securityRevision) != nil || securityRevision != expectedSecurityRevision {
		return false
	}
	issuedText, _ := localDpiCatalogString(payload["issued_at"])
	expiresText, _ := localDpiCatalogString(payload["expires_at"])
	issued, validIssued := smartAccessControlTime(issuedText)
	expires, validExpires := smartAccessControlTime(expiresText)
	if !validIssued || !validExpires || !issued.Before(expires) || now.Before(issued) || !now.Before(expires) {
		return false
	}
	if _, ok := localDpiCatalogArray(payload["sources"], 1, 128); !ok {
		return false
	}
	if _, ok := localDpiCatalogArray(payload["evidence"], 0, 512); !ok {
		return false
	}
	services, ok := localDpiCatalogArray(payload["services"], 1, 256)
	if !ok {
		return false
	}
	seen := make(map[string]bool, len(services))
	var selected map[string]json.RawMessage
	for _, raw := range services {
		service, valid := smartAccessControlObject(raw, "service_id", "display_name", "categories", "enabled", "classification",
			"reason", "evidence_status", "source_ids", "evidence_ids", "platforms", "access_states", "route_intents",
			"android", "windows", "domains", "networks", "provider_capability_refs", "external_gateway_policy")
		id, _ := localDpiCatalogString(service["service_id"])
		if !valid || !routingCatalogServiceID.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
		if id == serviceID {
			selected = service
		}
	}
	return selected != nil && localDpiCatalogService(selected, controlHost, accessState)
}

func localDpiCatalogPinnedKey(raw, keyID string) (ed25519.PublicKey, bool) {
	var values map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &values) != nil || len(values) == 0 {
		return nil, false
	}
	ids := make([]string, 0, len(values))
	for id := range values {
		if !routingCatalogServiceID.MatchString(id) {
			return nil, false
		}
		ids = append(ids, id)
	}
	object, ok := smartAccessControlObject([]byte(raw), ids...)
	if !ok {
		return nil, false
	}
	var selected ed25519.PublicKey
	for id, value := range object {
		encoded, valid := localDpiCatalogString(value)
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if !valid || len(encoded) != 44 || err != nil || len(key) != ed25519.PublicKeySize {
			return nil, false
		}
		if id == keyID {
			selected = ed25519.PublicKey(key)
		}
	}
	return selected, selected != nil
}

func localDpiCatalogService(service map[string]json.RawMessage, host, accessState string) bool {
	evidenceStatus, _ := localDpiCatalogString(service["evidence_status"])
	if string(service["enabled"]) != "true" || evidenceStatus != "verified" ||
		!localDpiCatalogContains(service["platforms"], "android") || !localDpiCatalogContains(service["access_states"], accessState) {
		return false
	}
	intents, ok := localDpiCatalogArray(service["route_intents"], 0, 5)
	if !ok {
		return false
	}
	seenModes := make(map[string]bool, len(intents))
	selectiveVPN := false
	for _, raw := range intents {
		intent, valid := smartAccessControlObject(raw, "mode", "action")
		if !valid {
			intent, valid = smartAccessControlObject(raw, "mode", "action", "local_dpi_control_host")
		}
		mode, _ := localDpiCatalogString(intent["mode"])
		action, _ := localDpiCatalogString(intent["action"])
		if !valid || mode == "" || seenModes[mode] {
			return false
		}
		seenModes[mode] = true
		if rawHost, present := intent["local_dpi_control_host"]; present {
			intentHost, _ := localDpiCatalogString(rawHost)
			if mode != "selective" || action != "vpn" || intentHost != host {
				return false
			}
			selectiveVPN = true
		}
		if mode == "selective" {
			if action != "vpn" {
				return false
			}
		}
	}
	if !selectiveVPN {
		return false
	}
	domains, ok := localDpiCatalogArray(service["domains"], 0, 256)
	if !ok {
		return false
	}
	seenDomains := make(map[string]bool, len(domains))
	foundHost := false
	for _, raw := range domains {
		domain, valid := smartAccessControlObject(raw, "name", "match", "role", "shared", "source_ids")
		name, _ := localDpiCatalogString(domain["name"])
		match, _ := localDpiCatalogString(domain["match"])
		shared := string(domain["shared"])
		identity := name + "\x00" + match
		if !valid || !localDpiCatalogHost(name) || (match != "exact" && match != "suffix") ||
			(shared != "false" && shared != "true") || seenDomains[identity] {
			return false
		}
		seenDomains[identity] = true
		if name == host {
			if match != "exact" || shared != "false" {
				return false
			}
			foundHost = true
		}
	}
	return foundHost
}

func localDpiCatalogContains(raw json.RawMessage, wanted string) bool {
	values, ok := localDpiCatalogArray(raw, 1, 5)
	if !ok {
		return false
	}
	seen := make(map[string]bool, len(values))
	found := false
	for _, raw := range values {
		value, valid := localDpiCatalogString(raw)
		if !valid || value == "" || seen[value] {
			return false
		}
		seen[value] = true
		found = found || value == wanted
	}
	return found
}

func localDpiCatalogArray(raw json.RawMessage, min, max int) ([]json.RawMessage, bool) {
	var values []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &values) != nil || len(values) < min || len(values) > max {
		return nil, false
	}
	return values, true
}

func localDpiCatalogString(raw json.RawMessage) (string, bool) {
	var value string
	err := json.Unmarshal(raw, &value)
	return value, err == nil && len(raw) > 0 && raw[0] == '"'
}

func localDpiCatalogHost(host string) bool {
	if len(host) < 3 || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

package daemon

import (
	"encoding/json"
	"testing"
)

func TestSmartAccessRenewalKeepsRoutingMode(t *testing.T) {
	identity := map[string]any{
		"lease_id": "0123456789abcdef0123456789abcdef", "platform": "android", "audience": "lab",
		"service_id": "ai", "provider_id": "owned", "permission_id": "owned", "capability_id": "ai-android",
		"provider_policy_revision": 1, "provider_security_revision": 1,
		"provider_policy_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"issued_at":              "2026-10-02T00:00:00Z", "new_flows_until": "2026-10-02T00:10:00Z", "active_flows_until": "2026-10-02T01:00:00Z",
		"profile_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"route_mode":     "smart_safe", "runtime_scope_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"origin": "synthetic", "family": "ipv4", "feature": "web_request",
		"provider_revision": 1, "permission_revision": 1, "catalog_revision": 1, "catalog_security_revision": 1,
	}
	raw, _ := json.Marshal(identity)
	previous, ok := parseSmartAccessRuntimeLeaseIdentity(raw)
	if !ok {
		t.Fatal("smart_safe renewal identity rejected")
	}
	identity["route_mode"] = "selective"
	raw, _ = json.Marshal(identity)
	next, ok := parseSmartAccessRuntimeLeaseIdentity(raw)
	if !ok {
		t.Fatal("DNS-only selective identity rejected")
	}
	if next.follows(previous) {
		t.Fatal("renewal changed the signed routing mode")
	}
	identity["route_mode"] = "full"
	raw, _ = json.Marshal(identity)
	if _, ok = parseSmartAccessRuntimeLeaseIdentity(raw); ok {
		t.Fatal("full-tunnel gateway authority accepted")
	}
}

package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/sagernet/sing-box/protocol/pokrov/smartaccess"
)

var smartAccessRuntimeRenewalCapability = regexp.MustCompile(`^pkr_srn1\.[A-Za-z0-9_-]+\.[a-f0-9]{64}$`)

// Same non-secret 23-field projection as the authenticated client. Raw grants,
// domains, relay addresses and account credentials never enter this structure.
type smartAccessRuntimeLeaseIdentity struct {
	LeaseID string `json:"lease_id"`
	Platform string `json:"platform"`
	Audience string `json:"audience"`
	ServiceID string `json:"service_id"`
	ProviderID string `json:"provider_id"`
	PermissionID string `json:"permission_id"`
	CapabilityID string `json:"capability_id"`
	ProviderPolicyRevision int64 `json:"provider_policy_revision"`
	ProviderSecurityRevision int64 `json:"provider_security_revision"`
	ProviderPolicySHA256 string `json:"provider_policy_sha256"`
	IssuedAt string `json:"issued_at"`
	NewFlowsUntil string `json:"new_flows_until"`
	ActiveFlowsUntil string `json:"active_flows_until"`
	ProfileSHA256 string `json:"profile_sha256"`
	RouteMode string `json:"route_mode"`
	RuntimeScopeSHA256 string `json:"runtime_scope_sha256"`
	Origin string `json:"origin"`
	Family string `json:"family"`
	Feature string `json:"feature"`
	ProviderRevision int64 `json:"provider_revision"`
	PermissionRevision int64 `json:"permission_revision"`
	CatalogRevision int64 `json:"catalog_revision"`
	CatalogSecurityRevision int64 `json:"catalog_security_revision"`
}

type smartAccessRuntimeRenewalConfig struct {
	SchemaVersion string `json:"schema_version"`
	ProfileDigest string `json:"profile_digest"`
	Capability string `json:"capability"`
	IssuedAt string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	Lease smartAccessRuntimeLeaseIdentity `json:"lease"`
}

type smartAccessRuntimeRenewal struct {
	config smartAccessRuntimeRenewalConfig
	current smartAccessRuntimeLeaseIdentity // Accepted generation, guarded by serviceAccess.
	lastAttempt time.Time
	issued time.Time
	expires time.Time
	deadline time.Time
	size int
}

// Stored recovery identities may be expired. Validate their original bounds,
// not current admission; live enrollment/application checks freshness separately.
func parseSmartAccessRuntimeLeaseIdentity(raw []byte) (smartAccessRuntimeLeaseIdentity, bool) {
	var lease smartAccessRuntimeLeaseIdentity
	if _, ok := smartAccessControlObject(raw, "lease_id", "platform", "audience", "service_id", "provider_id",
		"permission_id", "capability_id", "provider_policy_revision", "provider_security_revision", "provider_policy_sha256",
		"issued_at", "new_flows_until", "active_flows_until", "profile_sha256", "route_mode", "runtime_scope_sha256",
		"origin", "family", "feature", "provider_revision", "permission_revision", "catalog_revision", "catalog_security_revision"); !ok { return lease, false }
	if json.Unmarshal(raw, &lease) != nil || !smartAccessLeaseID.MatchString(lease.LeaseID) || lease.RouteMode != "selective" ||
		(lease.Platform != "android" && lease.Platform != "windows") || (lease.Audience != "lab" && lease.Audience != "production") ||
		(lease.Family != "ipv4" && lease.Family != "ipv6") { return lease, false }
	switch lease.Origin { case "current-origin", "brain-origin", "RU-origin", "synthetic": default: return lease, false }
	switch lease.Feature { case "web_request", "login", "streaming", "websocket", "store", "gameplay", "cloud_gaming": default: return lease, false }
	for _, id := range []string{lease.ServiceID, lease.ProviderID, lease.PermissionID, lease.CapabilityID} {
		if !routingCatalogServiceID.MatchString(id) { return lease, false }
	}
	for _, digest := range []string{lease.ProviderPolicySHA256, lease.ProfileSHA256, lease.RuntimeScopeSHA256} {
		if !smartAccessRuntimeDigest.MatchString(digest) { return lease, false }
	}
	for _, revision := range []int64{lease.ProviderPolicyRevision, lease.ProviderSecurityRevision, lease.ProviderRevision,
		lease.PermissionRevision, lease.CatalogRevision, lease.CatalogSecurityRevision} {
		if revision < 1 || revision > 9007199254740991 { return lease, false }
	}
	leaseIssued, leaseIssuedOK := smartAccessControlTime(lease.IssuedAt)
	newUntil, newOK := smartAccessControlTime(lease.NewFlowsUntil)
	activeUntil, activeOK := smartAccessControlTime(lease.ActiveFlowsUntil)
	return lease, leaseIssuedOK && newOK && activeOK && leaseIssued.Year() >= 1 &&
		leaseIssued.Before(newUntil) && !activeUntil.Before(newUntil) && newUntil.Sub(leaseIssued) <= 10*time.Minute &&
		activeUntil.Sub(leaseIssued) <= time.Hour
}

func (lease smartAccessRuntimeLeaseIdentity) follows(previous smartAccessRuntimeLeaseIdentity) bool {
	return lease.Platform == previous.Platform && lease.Audience == previous.Audience && lease.ServiceID == previous.ServiceID &&
		lease.ProviderID == previous.ProviderID && lease.PermissionID == previous.PermissionID && lease.CapabilityID == previous.CapabilityID &&
		lease.ProfileSHA256 == previous.ProfileSHA256 && lease.RouteMode == previous.RouteMode &&
		lease.RuntimeScopeSHA256 == previous.RuntimeScopeSHA256 && lease.Origin == previous.Origin &&
		lease.Family == previous.Family && lease.Feature == previous.Feature &&
		lease.ProviderRevision >= previous.ProviderRevision && lease.PermissionRevision >= previous.PermissionRevision &&
		lease.ProviderPolicyRevision >= previous.ProviderPolicyRevision && lease.ProviderSecurityRevision >= previous.ProviderSecurityRevision &&
		lease.CatalogRevision >= previous.CatalogRevision && lease.CatalogSecurityRevision >= previous.CatalogSecurityRevision
}

func (lease smartAccessRuntimeLeaseIdentity) canonicalObject() map[string]json.RawMessage {
	raw, _ := json.Marshal(lease)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	return fields
}

func parseSmartAccessRuntimeRenewal(raw string, now time.Time) (*smartAccessRuntimeRenewal, error) {
	invalid := errors.New("smart_access_runtime_renewal_invalid")
	if len(raw) > smartAccessRuntimeControlLimit { return nil, invalid }
	object, ok := smartAccessControlObject([]byte(raw), "schema_version", "profile_digest", "capability", "issued_at", "expires_at", "lease")
	if !ok { return nil, invalid }
	lease, ok := parseSmartAccessRuntimeLeaseIdentity(object["lease"])
	if !ok { return nil, invalid }
	var config smartAccessRuntimeRenewalConfig
	if json.Unmarshal([]byte(raw), &config) != nil || config.SchemaVersion != "pokrov-smart-access-runtime-renewal-worker-v1" ||
		!smartAccessRuntimeDigest.MatchString(config.ProfileDigest) || len(config.Capability) > 4096 ||
		!smartAccessRuntimeRenewalCapability.MatchString(config.Capability) { return nil, invalid }
	issued, issuedOK := smartAccessControlTime(config.IssuedAt)
	expires, expiresOK := smartAccessControlTime(config.ExpiresAt)
	leaseIssued, _ := smartAccessControlTime(lease.IssuedAt)
	newUntil, _ := smartAccessControlTime(lease.NewFlowsUntil)
	if !issuedOK || !expiresOK || now.Before(issued) || !issued.Before(expires) || !now.Before(expires) ||
		now.Before(leaseIssued) || !now.Before(newUntil) { return nil, invalid }
	return &smartAccessRuntimeRenewal{config: config, current: lease, issued: issued, expires: expires,
		deadline: now.Add(expires.Sub(now)), size: len(raw)}, nil
}

// Enrollment only: no HTTP request or lease extension is performed here. The
// native host authenticates/fences this sensitive command and invalidates saved
// profile reuse before dispatch. All enrollments disappear with the instance.
func (s *StartedService) ConfigureSmartAccessRenewal(profileDigest, raw string) (bool, error) {
	renewal, err := parseSmartAccessRuntimeRenewal(raw, time.Now())
	if err != nil { return false, err }
	if renewal.config.ProfileDigest != profileDigest { return false, errors.New("smart_access_runtime_renewal_conflict") }
	s.serviceAccess.Lock()
	defer s.serviceAccess.Unlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil { return false, errors.New("smart_access_runtime_unavailable") }
	worker := s.instance.smartAccessControl
	now := time.Now()
	lease := renewal.config.Lease
	if worker == nil || worker.ctx.Err() != nil || worker.config.ProfileDigest != profileDigest ||
		worker.config.Platform != lease.Platform || worker.config.Audience != lease.Audience ||
		!now.Before(worker.expires) || !now.Before(worker.deadline) || !now.Before(renewal.expires) ||
		!now.Before(renewal.deadline) || now.Before(renewal.issued) || renewal.expires.After(worker.expires) {
		return false, errors.New("smart_access_runtime_renewal_conflict")
	}
	found := false
	for _, outbound := range s.instance.instance.Outbound().Outbounds() {
		if target, ok := outbound.(*smartaccess.Outbound); ok &&
			target.AcceptsRenewalEnrollment(lease.LeaseID, lease.IssuedAt, lease.NewFlowsUntil, lease.ActiveFlowsUntil) { found = true; break }
	}
	if !found { return false, nil }
	if worker.renewals == nil { worker.renewals = make(map[string]*smartAccessRuntimeRenewal) }
	for scope, retained := range worker.renewals {
		if !now.Before(retained.expires) || !now.Before(retained.deadline) { delete(worker.renewals, scope) }
	}
	previous := worker.renewals[lease.RuntimeScopeSHA256]
	if previous != nil {
		if renewal.issued.Before(previous.issued) { return false, errors.New("smart_access_runtime_renewal_conflict") }
		if previous.config.Capability == renewal.config.Capability {
			old, _ := json.Marshal(previous.config)
			next, _ := json.Marshal(renewal.config)
			if !bytes.Equal(old, next) { return false, errors.New("smart_access_runtime_renewal_conflict") }
			return true, nil // Keep the original monotonic deadline on an exact retry.
		}
		if !lease.follows(previous.current) {
			return false, errors.New("smart_access_runtime_renewal_conflict")
		}
	}
	size := renewal.size
	for scope, retained := range worker.renewals { if scope != lease.RuntimeScopeSHA256 { size += retained.size } }
	if (previous == nil && len(worker.renewals) >= 256) || size > 1024*1024 { return false, errors.New("smart_access_runtime_renewal_full") }
	worker.renewals[lease.RuntimeScopeSHA256] = renewal
	return true, nil
}

package daemon

import (
	"errors"
	"encoding/json"
	"regexp"
	"sort"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/pokrov/smartaccess"
)

var smartAccessLeaseID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Snapshot current generations, not retained historical IDs. The authenticated
// native host fences the profile; a later renewal still compares the exact ID.
func (s *StartedService) ReadSmartAccessLeases() (string, error) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return "", errors.New("smart_access_runtime_unavailable")
	}
	ids := make([]string, 0)
	selections := make([]smartaccess.ServiceLeaseSelection, 0)
	seenServices := make(map[string]bool)
	for _, outbound := range s.instance.instance.Outbound().Outbounds() {
		if lease, ok := outbound.(*smartaccess.Outbound); ok {
			ids = append(ids, lease.LeaseID())
			if len(ids) > 256 { return "", errors.New("smart_access_runtime_inventory_full") }
			if selection := lease.ReadServiceLeaseSelection(); selection != nil {
				if seenServices[selection.ServiceID] { return "", errors.New("smart_access_runtime_inventory_invalid") }
				seenServices[selection.ServiceID] = true
				selections = append(selections, *selection)
			}
		}
	}
	sort.Strings(ids)
	sort.Slice(selections, func(i, j int) bool { return selections[i].ServiceID < selections[j].ServiceID })
	encoded, err := json.Marshal(map[string]any{"schema": 1, "lease_ids": ids, "selections": selections})
	if err != nil || len(encoded) > 65536 { return "", errors.New("smart_access_runtime_inventory_invalid") }
	return string(encoded), nil
}

// Called only after Box has accepted this profile. Retain dates, never profile
// bytes, so crash recovery does not depend on Flutter's lease inventory.
func smartAccessProfileRestrictionExpiry(options option.Options) time.Time {
	var expires time.Time
	retain := func(value string) {
		if parsed, ok := smartAccessControlTime(value); ok && parsed.After(expires) { expires = parsed }
	}
	var routeRules func([]option.Rule)
	routeRules = func(rules []option.Rule) {
		for _, rule := range rules {
			if window := rule.DefaultOptions.PokrovCatalogWindow; window != nil { retain(window.ExpiresAt) }
			routeRules(rule.LogicalOptions.Rules)
		}
	}
	var dnsRules func([]option.DNSRule)
	dnsRules = func(rules []option.DNSRule) {
		for _, rule := range rules {
			if window := rule.DefaultOptions.PokrovCatalogWindow; window != nil { retain(window.ExpiresAt) }
			dnsRules(rule.LogicalOptions.Rules)
		}
	}
	if options.Route != nil { routeRules(options.Route.Rules) }
	if options.DNS != nil { dnsRules(options.DNS.Rules) }
	for _, outbound := range options.Outbounds {
		if lease, ok := outbound.Options.(*option.PokrovSmartAccessOutboundOptions); ok { retain(lease.ActiveFlowsUntil) }
	}
	return expires
}

// The authenticated host verifies the grant, persists old/new restriction
// identities and fences the running profile. Core does not issue a lease.
func (s *StartedService) RenewSmartAccessLease(expectedID, nextID, issuedAt, newFlowsUntil, activeFlowsUntil string) (bool, error) {
	if !smartAccessLeaseID.MatchString(expectedID) { return false, errors.New("smart_access_lease_invalid") }
	s.serviceAccess.Lock()
	defer s.serviceAccess.Unlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return false, errors.New("smart_access_runtime_unavailable")
	}
	for _, outbound := range s.instance.instance.Outbound().Outbounds() {
		if lease, ok := outbound.(*smartaccess.Outbound); ok {
			found, err := lease.RenewLease(expectedID, nextID, issuedAt, newFlowsUntil, activeFlowsUntil, func(expires time.Time) error {
				instance := s.instance
				if !expires.After(instance.smartAccessRestrictionExpires) { return nil }
				if worker := instance.smartAccessControl; worker != nil {
					if err := worker.journal.extendExpiry(worker.config.ProfileDigest, worker.journalGeneration, expires); err != nil { return err }
				}
				instance.smartAccessRestrictionExpires = expires
				return nil
			})
			if err != nil || found { return found, err }
		}
	}
	return false, nil
}

// RevokeSmartAccessPolicy restricts every actual lease in the running profile.
// The authenticated host fences that profile; ordinary catalog rules stay intact.
func (s *StartedService) RevokeSmartAccessPolicy(terminateActive bool) (bool, error) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return false, errors.New("smart_access_runtime_unavailable")
	}
	found := false
	for _, outbound := range s.instance.instance.Outbound().Outbounds() {
		if lease, ok := outbound.(*smartaccess.Outbound); ok {
			lease.Revoke(terminateActive)
			found = true
		}
	}
	return found, nil
}

// RevokeSmartAccessLease targets an exact grant, not a tag that a subsequent
// profile can reuse. The host authenticates the decision and chooses whether
// safety requires terminating active flows. Missing leases change nothing.
func (s *StartedService) RevokeSmartAccessLease(leaseID string, terminateActive bool) (bool, error) {
	if !smartAccessLeaseID.MatchString(leaseID) { return false, errors.New("smart_access_lease_invalid") }
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return false, errors.New("smart_access_runtime_unavailable")
	}
	found := false
	for _, outbound := range s.instance.instance.Outbound().Outbounds() {
		if lease, ok := outbound.(*smartaccess.Outbound); ok {
			if lease.RevokeLease(leaseID, terminateActive) { found = true }
		}
	}
	return found, nil
}

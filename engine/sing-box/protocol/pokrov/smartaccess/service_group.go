package smartaccess

import (
	"sort"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

// Execute the coordinator's preverified provider order. No new ranking, probe,
// grant, profile mutation or migration of existing connections occurs here.
type ServiceLeaseGroup struct {
	mu sync.Mutex
	serviceID string
	members []*Outbound
	selected int
	evaluated bool
	dnsFailed map[*Outbound]bool
	probeWindows []*serviceProbeWindow
}

type serviceProbeWindow struct {
	member *Outbound
	dns bool
	transport adapter.DNSTransport
	active func() bool
	current func(string) bool
}

// A scoped probe must retain both real compiled rule windows. Closing a rule
// removes its binding; active checks only the catalog window, independently of
// the member's lease. Checking that lease alone cannot extend a catalog.
func (group *ServiceLeaseGroup) BindProbeWindow(member *Outbound, dns bool, transport adapter.DNSTransport, active func() bool, current func(string) bool) func() {
	window := &serviceProbeWindow{member: member, dns: dns, transport: transport, active: active, current: current}
	group.mu.Lock()
	group.probeWindows = append(group.probeWindows, window)
	group.mu.Unlock()
	return func() {
		group.mu.Lock()
		defer group.mu.Unlock()
		for index, bound := range group.probeWindows {
			if bound == window {
				group.probeWindows = append(group.probeWindows[:index], group.probeWindows[index+1:]...)
				return
			}
		}
	}
}

func (group *ServiceLeaseGroup) probeScope(member *Outbound, domain string, selected bool) (adapter.DNSTransport, bool) {
	if !member.AdmitsNewFlows() { return nil, false }
	if selected && group.Selected() != member { return nil, false }
	group.mu.Lock()
	windows := append([]*serviceProbeWindow(nil), group.probeWindows...)
	group.mu.Unlock()
	var transport adapter.DNSTransport
	var route bool
	for _, window := range windows {
		if window.member != member || !window.active() || (selected && !window.current(domain)) { continue }
		if window.dns { transport = window.transport } else { route = true }
	}
	return transport, route && transport != nil && (!selected || group.Selected() == member)
}

// Expiry is a recoverable grant outcome only while the actual compiled catalog
// windows remain current. Revocation, withdrawn scope and resolver retirement
// must keep their distinct authority/lifecycle outcome.
func (group *ServiceLeaseGroup) probeGrantsExpired(manager adapter.DNSTransportManager) bool {
	if manager == nil {
		return false
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	// Outbound tags are immutable and manager-unique; overlapping groups must
	// lock their grants in the same order while renewal/revoke is excluded.
	members := append([]*Outbound(nil), group.members...)
	sort.Slice(members, func(i, j int) bool { return members[i].Tag() < members[j].Tag() })
	for _, member := range members {
		member.mu.Lock()
		defer member.mu.Unlock()
	}
	now := time.Now()
	for _, member := range group.members {
		lease := member.lease
		if member.closed || member.revoked || lease.revoked || group.dnsFailed[member] || now.Before(lease.issued) ||
			(now.Before(lease.newUntil) && now.Before(lease.newDeadline)) {
			return false
		}
		var dns, route bool
		for _, window := range group.probeWindows {
			if window.member != member || !window.active() {
				continue
			}
			if !window.dns {
				route = true
			} else if window.transport != nil {
				bound, ok := manager.Transport(window.transport.Tag())
				dns = ok && bound == window.transport
			}
		}
		if !dns || !route {
			return false
		}
	}
	return true
}

func (h *Outbound) ServiceLeaseGroup(serviceID string, members []*Outbound) (*ServiceLeaseGroup, error) {
	if serviceID == "" || len(members) == 0 || len(members) > 16 || members[0] != h { return nil, errScope }
	seen := make(map[*Outbound]bool, len(members))
	domains := make(map[option.PokrovSmartAccessDomain]bool, len(h.domains))
	for _, domain := range h.domains { domains[domain] = true }
	for _, member := range members {
		if member == nil || seen[member] || len(member.domains) != len(domains) { return nil, errScope }
		for _, domain := range member.domains { if !domains[domain] { return nil, errScope } }
		seen[member] = true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.serviceGroup != nil {
		group := h.serviceGroup
		if group.serviceID != serviceID || len(group.members) != len(members) { return nil, errScope }
		for index, member := range members { if group.members[index] != member { return nil, errScope } }
		return group, nil
	}
	h.serviceGroup = &ServiceLeaseGroup{serviceID: serviceID, members: append([]*Outbound(nil), members...)}
	return h.serviceGroup, nil
}

func (group *ServiceLeaseGroup) Selected() *Outbound {
	group.mu.Lock()
	defer group.mu.Unlock()
	group.evaluated = true
	if group.selected >= 0 && !group.dnsFailed[group.members[group.selected]] && group.members[group.selected].availableForNewFlows() { return group.members[group.selected] }
	for index, member := range group.members {
		if !group.dnsFailed[member] && member.availableForNewFlows() { group.selected = index; return member }
	}
	group.selected = -1
	return nil
}

// A failed provider resolver cannot supply DNS for a new connection through
// another provider. Retire this candidate for the remaining profile lifetime;
// the next matching DNS/route rule chooses a standby or scoped fallback.
func (group *ServiceLeaseGroup) DNSFailed(member *Outbound) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.dnsFailed == nil { group.dnsFailed = make(map[*Outbound]bool) }
	group.dnsFailed[member] = true
	if group.selected >= 0 && group.members[group.selected] == member { group.selected = -1 }
}

type ServiceLeaseSelection struct {
	ServiceID string `json:"service_id"`
	LeaseID string `json:"lease_id"`
	SelectionIndex int `json:"selection_index"`
	State string `json:"state"`
	Available bool `json:"available"`
}

// Only the anchor exports a row. Readback never selects another provider.
func (h *Outbound) ReadServiceLeaseSelection() *ServiceLeaseSelection {
	h.mu.Lock()
	group := h.serviceGroup
	h.mu.Unlock()
	if group == nil { return nil }
	group.mu.Lock()
	defer group.mu.Unlock()
	result := &ServiceLeaseSelection{ServiceID: group.serviceID, SelectionIndex: group.selected, State: "pending"}
	if group.selected < 0 {
		result.State = "unavailable"
		return result
	}
	member := group.members[group.selected]
	result.LeaseID = member.LeaseID()
	result.Available = member.availableForNewFlows()
	if group.evaluated { result.State = "gateway" }
	return result
}

// This is a read of local admission/transport state, not a provider-health
// assertion or a half-open reservation. The actual dial rechecks all limits.
func (h *Outbound) availableForNewFlows() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if !h.admitsLocked(now) || len(h.flows) >= h.maxConcurrent { return false }
	for len(h.attempts) > 0 && now.Sub(h.attempts[0]) >= time.Minute { h.attempts = h.attempts[1:] }
	if len(h.attempts) >= h.maxNew { return false }
	if h.relayPolicy == nil { return true }
	for _, state := range h.relayStates {
		if state.openUntil.IsZero() || (!state.probing && !now.Before(state.openUntil)) { return true }
	}
	return false
}

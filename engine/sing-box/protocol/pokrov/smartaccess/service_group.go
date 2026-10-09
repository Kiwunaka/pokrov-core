package smartaccess

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
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
	probeID uint64
	readiness *serviceReadinessProbe
	fallbackGuardClosed bool
}

type ServiceReadinessStage struct {
	Stage        string `json:"stage"`
	Result       string `json:"result"`
	ObservedAtMS int64  `json:"observed_at_ms"`
	DurationMS   int64  `json:"duration_ms"`
	Reason       string `json:"reason,omitempty"`
}

type ServiceReadiness struct {
	ProbeID             uint64                  `json:"probe_id"`
	LeaseID             string                  `json:"lease_id"`
	StartedAtMS         int64                   `json:"started_at_ms"`
	CompletedAtMS       *int64                  `json:"completed_at_ms"`
	Status              string                  `json:"status"`
	Stages              []ServiceReadinessStage `json:"stages"`
	FallbackGuardClosed bool                    `json:"fallback_guard_closed"`
}

type serviceReadinessProbe struct {
	ServiceReadiness
	member            *Outbound
	ctx, ownerContext context.Context
	transport         adapter.DNSTransport
	manager           adapter.DNSTransportManager
}

// A new probe replaces every stage from the previous attempt. The closed guard
// survives later probes until this compiled service group is replaced.
func (group *ServiceLeaseGroup) beginReadiness(ctx, ownerContext context.Context) *serviceReadinessProbe {
	group.mu.Lock()
	defer group.mu.Unlock()
	previous := group.readiness
	if previous != nil && previous.member != nil && !group.readinessCurrentLocked(previous) {
		group.closeReadinessLocked()
	}
	group.probeID++
	probe := &serviceReadinessProbe{ServiceReadiness: ServiceReadiness{
		ProbeID: group.probeID, StartedAtMS: time.Now().UnixMilli(), Status: "pending",
		Stages: []ServiceReadinessStage{}, FallbackGuardClosed: group.fallbackGuardClosed,
	}, ctx: ctx, ownerContext: ownerContext}
	// Keep the guard bound while the new probe captures its current member.
	// Stages and completion always belong only to this new probe.
	if previous != nil {
		probe.member, probe.LeaseID, probe.transport, probe.manager = previous.member, previous.LeaseID, previous.transport, previous.manager
	}
	group.readiness = probe
	return probe
}

func (group *ServiceLeaseGroup) bindReadiness(probe *serviceReadinessProbe, member *Outbound, leaseID string, transport adapter.DNSTransport, manager adapter.DNSTransportManager) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.readiness != probe {
		return
	}
	probe.member, probe.LeaseID, probe.transport, probe.manager = member, leaseID, transport, manager
}

// Unlike probeScope, this only peeks. Reading receipts never selects a provider
// or extends catalog/lease authority.
func (group *ServiceLeaseGroup) readinessCurrentLocked(probe *serviceReadinessProbe) bool {
	if (probe.Status == "pending" && probe.ctx.Err() != nil) || probe.ownerContext.Err() != nil ||
		probe.member == nil || group.selected < 0 || group.members[group.selected] != probe.member ||
		probe.manager == nil || probe.transport == nil {
		return false
	}
	probe.member.mu.Lock()
	currentLease := probe.member.lease.id == probe.LeaseID && probe.member.admitsLocked(time.Now())
	probe.member.mu.Unlock()
	if !currentLease {
		return false
	}
	bound, ok := probe.manager.Transport(probe.transport.Tag())
	if !ok || bound != probe.transport {
		return false
	}
	var dns, route bool
	for _, window := range group.probeWindows {
		if window.member != probe.member || !window.active() {
			continue
		}
		if window.dns {
			dns = dns || window.transport == probe.transport
		} else {
			route = true
		}
	}
	return dns && route
}

func (group *ServiceLeaseGroup) closeReadinessLocked() {
	if group.readiness == nil {
		return
	}
	group.fallbackGuardClosed = true
	probe := group.readiness
	probe.FallbackGuardClosed = true
	if probe.Status != "failure" {
		observedAt := time.Now().UnixMilli()
		probe.CompletedAtMS, probe.Status = &observedAt, "failure"
	}
}

func (group *ServiceLeaseGroup) observeReadiness(probe *serviceReadinessProbe, stage string, observedAt time.Time, duration time.Duration, err error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.readiness != probe {
		return
	}
	if probe.ctx.Err() != nil || !group.readinessCurrentLocked(probe) {
		group.closeReadinessLocked()
		return
	}
	result := "pass"
	if err != nil {
		result = "failure"
	}
	probe.Stages = append(probe.Stages, ServiceReadinessStage{
		Stage: stage, Result: result, ObservedAtMS: observedAt.UnixMilli(), DurationMS: duration.Milliseconds(),
		Reason: urltest.ObservedFailure(err),
	})
	if err != nil {
		group.closeReadinessLocked()
	}
}

func (group *ServiceLeaseGroup) finishReadiness(probe *serviceReadinessProbe, err error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.readiness != probe {
		return
	}
	if err != nil || probe.ctx.Err() != nil || group.fallbackGuardClosed || !group.readinessCurrentLocked(probe) || len(probe.Stages) != 3 ||
		probe.Stages[0].Stage != "resolver" || probe.Stages[1].Stage != "dns" || probe.Stages[2].Stage != "tls" ||
		probe.Stages[0].Result != "pass" || probe.Stages[1].Result != "pass" || probe.Stages[2].Result != "pass" {
		group.closeReadinessLocked()
		return
	}
	completedAt := time.Now().UnixMilli()
	probe.CompletedAtMS, probe.Status = &completedAt, "pass"
}

// A real rule walk skipped the captured provider for one of its service
// domains. Close the QA guard even if normal routing later chooses that member
// again. This does not change the rule result or record traffic contents.
func (group *ServiceLeaseGroup) ObserveScopedRuleBypass(member *Outbound, domain string) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.readiness != nil && group.readiness.member == member &&
		member.allows(strings.ToLower(strings.TrimSuffix(domain, "."))) {
		group.closeReadinessLocked()
	}
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
				if group.readiness != nil && group.readiness.member == member { group.closeReadinessLocked() }
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

// Retain a real current-grant failure or admission expiry only while the actual
// compiled catalog windows remain current. Missing authority is never converted
// into provider failure or a recoverable grant expiry.
func (group *ServiceLeaseGroup) probeUnavailableError(manager adapter.DNSTransportManager) error {
	if manager == nil {
		return nil
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
	var failure *urltest.ProbeError
	for _, member := range group.members {
		lease := member.lease
		if member.closed || member.revoked || lease.revoked || now.Before(lease.issued) {
			return nil
		}
		expired := !now.Before(lease.newUntil) || !now.Before(lease.newDeadline)
		if expired {
			if group.dnsFailed[member] { return nil }
		} else {
			if lease.admissionExpired || (lease.probeFailure == nil && !group.dnsFailed[member]) { return nil }
			if failure == nil {
				if group.dnsFailed[member] {
					// The same resolver stays retired for this profile even when a
					// signed renewal replaces only the grant identity/deadlines.
					failure = &urltest.ProbeError{Stage: urltest.ProbeStageDNS, Err: errScope}
				} else { failure = lease.probeFailure }
			}
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
			return nil
		}
	}
	if failure != nil { return failure }
	return &urltest.ProbeError{Stage: urltest.ProbeStageLeaseExpired, Err: errLease}
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
	defer func() {
		if probe := group.readiness; probe != nil && probe.member != nil &&
			(group.selected < 0 || group.members[group.selected] != probe.member) { group.closeReadinessLocked() }
	}()
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
	if group.readiness != nil && group.readiness.member == member { group.closeReadinessLocked() }
	member.mu.Lock()
	if member.admitsLocked(time.Now()) {
		member.lease.probeFailure = &urltest.ProbeError{Stage: urltest.ProbeStageDNS, Err: errScope}
	}
	member.mu.Unlock()
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
	Readiness *ServiceReadiness `json:"readiness"`
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
	if probe := group.readiness; probe != nil {
		if probe.member != nil && !group.readinessCurrentLocked(probe) {
			group.closeReadinessLocked()
		}
		snapshot := probe.ServiceReadiness
		snapshot.Stages = append([]ServiceReadinessStage{}, probe.Stages...)
		if probe.CompletedAtMS != nil {
			completedAt := *probe.CompletedAtMS
			snapshot.CompletedAtMS = &completedAt
		}
		result.Readiness = &snapshot
	}
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

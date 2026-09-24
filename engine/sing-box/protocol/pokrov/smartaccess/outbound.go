package smartaccess

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const Type = "pokrov-smart-access"
const timeLayout = "2006-01-02T15:04:05Z"
var errLease = errors.New("smart_access_lease_unavailable")
var errScope = errors.New("smart_access_flow_unsupported")
var leaseIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var domainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PokrovSmartAccessOutboundOptions](registry, Type, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	dialer N.Dialer
	connection adapter.ConnectionManager
	relays []M.Socksaddr
	relayPolicy *option.PokrovRelayConnectPolicy
	relayStates []relayConnectState // Guarded by mu; scoped to this outbound.
	preferredRelay int
	serviceGroup *ServiceLeaseGroup // Shared by service route and DNS windows.
	domains []option.PokrovSmartAccessDomain
	lease *leaseAuthorization
	leases map[string]*leaseAuthorization
	maxNew, maxConcurrent int
	mu sync.Mutex
	closed bool
	revoked bool
	terminateActive bool
	attempts []time.Time
	flows map[*leaseFlow]struct{}
}

// Dates and identity never change after construction. Revocation/admission
// latches are guarded by the outbound mutex, and every flow retains this object.
type leaseAuthorization struct {
	id string
	issued, newUntil, activeUntil time.Time
	newDeadline, activeDeadline time.Time
	admissionExpired bool
	revoked bool
	terminateActive bool
}

func newLeaseAuthorization(id, issuedAt, newFlowsUntil, activeFlowsUntil string) (*leaseAuthorization, error) {
	parse := func(value string) (time.Time, error) {
		parsed, err := time.Parse(timeLayout, value)
		if err != nil || parsed.Year() < 1 || parsed.Format(timeLayout) != value { return time.Time{}, errLease }
		return parsed, nil
	}
	issued, err := parse(issuedAt)
	if err != nil { return nil, err }
	newUntil, err := parse(newFlowsUntil)
	if err != nil { return nil, err }
	activeUntil, err := parse(activeFlowsUntil)
	if err != nil { return nil, err }
	now := time.Now()
	if !leaseIDPattern.MatchString(id) || !newUntil.After(issued) || activeUntil.Before(newUntil) ||
		newUntil.Sub(issued) > 10*time.Minute || activeUntil.Sub(issued) > time.Hour || now.Before(issued) {
		return nil, errLease
	}
	return &leaseAuthorization{id: id, issued: issued, newUntil: newUntil, activeUntil: activeUntil,
		newDeadline: now.Add(newUntil.Sub(now)), activeDeadline: now.Add(activeUntil.Sub(now)),
		admissionExpired: !now.Before(newUntil)}, nil
}

func NewOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.PokrovSmartAccessOutboundOptions) (adapter.Outbound, error) {
	lease, err := newLeaseAuthorization(options.LeaseID, options.IssuedAt, options.NewFlowsUntil, options.ActiveFlowsUntil)
	if err != nil { return nil, err }
	if options.MaxNewConnectionsPerMinute < 1 || options.MaxNewConnectionsPerMinute > 10000 ||
		options.MaxConcurrentConnections < 1 || options.MaxConcurrentConnections > 256 || len(options.Domains) == 0 || len(options.Domains) > 256 {
		return nil, errLease
	}
	if len(options.RelayAddresses) < 1 || len(options.RelayAddresses) > 8 || !validRelayConnectPolicy(options.RelayConnectPolicy) {
		return nil, errLease
	}
	relays := make([]M.Socksaddr, 0, len(options.RelayAddresses))
	seenRelay := make(map[netip.Addr]bool)
	for _, value := range options.RelayAddresses {
		relay, err := netip.ParseAddr(value)
		if err != nil || !publicRelayAddress(relay) || seenRelay[relay] { return nil, errScope }
		seenRelay[relay] = true
		relays = append(relays, M.Socksaddr{Addr: relay, Port: 443})
	}
	if options.Detour != "" { return nil, errScope }
	seen := make(map[option.PokrovSmartAccessDomain]bool)
	for _, domain := range options.Domains {
		name, err := normalizeDomain(domain.Name)
		if err != nil || name != domain.Name || (domain.Match != "exact" && domain.Match != "suffix") || seen[domain] {
			return nil, errScope
		}
		seen[domain] = true
	}
	transport, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx, Options: options.DialerOptions, ProtectPlatformSocket: true,
	})
	if err != nil { return nil, errScope }
	manager := service.FromContext[adapter.ConnectionManager](ctx)
	if manager == nil { return nil, errLease }
	return &Outbound{
		Adapter: outbound.NewAdapter(Type, tag, []string{N.NetworkTCP}, nil), dialer: transport, connection: manager,
		relays: relays, relayPolicy: options.RelayConnectPolicy, relayStates: make([]relayConnectState, len(relays)),
		domains: append([]option.PokrovSmartAccessDomain(nil), options.Domains...),
		lease: lease, leases: map[string]*leaseAuthorization{lease.id: lease},
		maxNew: options.MaxNewConnectionsPerMinute, maxConcurrent: options.MaxConcurrentConnections,
		flows: make(map[*leaseFlow]struct{}),
	}, nil
}

func (h *Outbound) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed { return errLease }
	return nil
}

func (h *Outbound) Close() error {
	h.mu.Lock()
	h.closed = true
	h.terminateActive = true
	flows := make([]*leaseFlow, 0, len(h.flows))
	for flow := range h.flows { flows = append(flows, flow) }
	h.mu.Unlock()
	for _, flow := range flows { _ = flow.Close() }
	return nil
}

// Keep the outbound registered after revocation: its route remains a rejection,
// never a missing target that can change the manager's default outbound.
func (h *Outbound) LeaseID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lease.id
}

// Enrollment cannot bind a credential to an expired, revoked, replaced or
// merely historical generation. Compare the dates already accepted by Core.
func (h *Outbound) AcceptsRenewalEnrollment(id, issuedAt, newFlowsUntil, activeFlowsUntil string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lease.id == id && h.lease.issued.Format(timeLayout) == issuedAt &&
		h.lease.newUntil.Format(timeLayout) == newFlowsUntil && h.lease.activeUntil.Format(timeLayout) == activeFlowsUntil &&
		h.admitsLocked(time.Now())
}

// A fresh signed grant may renew an expired admission window, but never a
// received revocation or a historical generation superseded by another owner.
func (h *Outbound) CanRenewLease(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.closed && !h.revoked && !h.lease.revoked && h.lease.id == id
}

// The host must verify a fresh grant for the same provider, capability, relay,
// resolver, domain scope and quotas. This primitive only replaces authority
// dates/identity; it cannot change egress or remove a received restriction.
func (h *Outbound) RenewLease(expectedID, nextID, issuedAt, newFlowsUntil, activeFlowsUntil string, retainExpiry func(time.Time) error) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, found := h.leases[expectedID]; !found { return false, nil }
	if h.closed || h.revoked || h.lease.revoked { return false, errLease }
	next, err := newLeaseAuthorization(nextID, issuedAt, newFlowsUntil, activeFlowsUntil)
	if err != nil || next.admissionExpired { return false, errLease }
	if h.lease.id == nextID && h.lease.issued.Equal(next.issued) &&
		h.lease.newUntil.Equal(next.newUntil) && h.lease.activeUntil.Equal(next.activeUntil) {
		// An idempotent retry must never reset a monotonic deadline.
		return true, nil
	}
	if h.lease.id != expectedID || nextID == expectedID || next.issued.Before(h.lease.issued) ||
		!next.newUntil.After(h.lease.newUntil) { return false, errLease }
	if _, reused := h.leases[nextID]; reused { return false, errLease }
	now := time.Now()
	for id, retained := range h.leases {
		if id != expectedID && (!now.Before(retained.activeUntil) || !now.Before(retained.activeDeadline)) { delete(h.leases, id) }
	}
	// Same bound as the retained host lease inventory. Renewal cannot build an
	// unbounded history of identities inside a long-lived outbound.
	if len(h.leases) >= 256 { return false, errLease }
	// Commit recovery bounds before granting authority. A late persistence
	// completion cannot revive an already expired candidate.
	if err := retainExpiry(next.activeUntil); err != nil { return false, err }
	now = time.Now()
	if now.Before(next.issued) || !now.Before(next.newUntil) || !now.Before(next.newDeadline) { return false, errLease }
	h.leases[nextID] = next
	h.lease = next
	return true, nil
}

// Route and DNS rules use the same admission latch as relay connections.
// This read never reserves a relay flow or changes its egress.
func (h *Outbound) AdmitsNewFlows() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.admitsLocked(time.Now())
}

func (h *Outbound) Revoke(terminateActive bool) {
	h.mu.Lock()
	h.revoked = true
	if terminateActive { h.terminateActive = true }
	flows := make([]*leaseFlow, 0, len(h.flows))
	for flow := range h.flows {
		if terminateActive || !flow.active { flows = append(flows, flow) }
	}
	h.mu.Unlock()
	for _, flow := range flows { _ = flow.Close() }
}

// Old leases remain addressable until their original active deadline, including
// idempotent retry after their final flow closes. Another generation is untouched.
func (h *Outbound) RevokeLease(leaseID string, terminateActive bool) bool {
	h.mu.Lock()
	lease, found := h.leases[leaseID]
	if !found { h.mu.Unlock(); return false }
	lease.revoked = true
	if terminateActive { lease.terminateActive = true }
	flows := make([]*leaseFlow, 0, len(h.flows))
	for flow := range h.flows {
		if flow.authorization == lease && (terminateActive || !flow.active) { flows = append(flows, flow) }
	}
	h.mu.Unlock()
	for _, flow := range flows { _ = flow.Close() }
	return true
}

// A caller cannot bypass ClientHello admission by using this as a raw dialer.
func (h *Outbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) { return nil, errScope }
func (h *Outbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) { return nil, errScope }

func (h *Outbound) admitsLocked(now time.Time) bool {
	return h.admitsLeaseLocked(h.lease, now)
}

func (h *Outbound) admitsLeaseLocked(lease *leaseAuthorization, now time.Time) bool {
	if now.Before(lease.issued) || !now.Before(lease.newUntil) || !now.Before(lease.newDeadline) {
		lease.admissionExpired = true
	}
	return !h.closed && !h.revoked && !lease.revoked && !lease.admissionExpired
}

func (h *Outbound) allows(name string) bool {
	for _, domain := range h.domains {
		if name == domain.Name || (domain.Match == "suffix" && strings.HasSuffix(name, "."+domain.Name)) { return true }
	}
	return false
}

func (h *Outbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if metadata.Destination.Port != 443 {
		N.CloseOnHandshakeFailure(conn, onClose, errScope)
		return
	}
	now := time.Now()
	h.mu.Lock()
	for len(h.attempts) > 0 && now.Sub(h.attempts[0]) >= time.Minute { h.attempts = h.attempts[1:] }
	if !h.admitsLocked(now) || len(h.flows) >= h.maxConcurrent || len(h.attempts) >= h.maxNew {
		h.mu.Unlock()
		N.CloseOnHandshakeFailure(conn, onClose, errLease)
		return
	}
	flowCtx, cancel := context.WithCancel(ctx)
	flow := &leaseFlow{Conn: conn, owner: h, authorization: h.lease, cancel: cancel}
	h.flows[flow] = struct{}{}
	flow.mu.Lock()
	flow.timer = time.AfterFunc(time.Until(flow.authorization.activeDeadline), func() { _ = flow.Close() })
	flow.mu.Unlock()
	h.attempts = append(h.attempts, now)
	h.mu.Unlock()
	stopCancel := context.AfterFunc(flowCtx, func() { _ = flow.Close() })
	finish := N.OnceClose(func(err error) {
		stopCancel()
		_ = flow.Close()
		if onClose != nil { onClose(err) }
	})
	// Explicit connect budget includes ClientHello and all relay attempts, and
	// can only shorten the original lease admission deadline.
	connectDeadline := flow.authorization.newDeadline
	if h.relayPolicy != nil {
		budgetDeadline := now.Add(time.Duration(h.relayPolicy.TotalTimeoutMS) * time.Millisecond)
		if budgetDeadline.Before(connectDeadline) { connectDeadline = budgetDeadline }
	}
	if err := flow.SetReadDeadline(connectDeadline); err != nil {
		N.CloseOnHandshakeFailure(flow, finish, errScope)
		return
	}
	raw, serverName, err := readClientHello(flow)
	if err != nil || !h.allows(serverName) {
		N.CloseOnHandshakeFailure(flow, finish, errScope)
		return
	}
	h.mu.Lock()
	allowed := h.admitsLeaseLocked(flow.authorization, time.Now())
	h.mu.Unlock()
	if !allowed { N.CloseOnHandshakeFailure(flow, finish, errLease); return }
	dialCtx, stopDial := context.WithDeadline(flowCtx, connectDeadline)
	remote, err := h.connectRelay(dialCtx, flow.authorization)
	stopDial()
	if err != nil { N.CloseOnHandshakeFailure(flow, finish, errLease); return }
	if !flow.setRemote(remote) { _ = remote.Close(); N.CloseOnHandshakeFailure(flow, finish, errLease); return }
	h.mu.Lock()
	allowed = h.admitsLeaseLocked(flow.authorization, time.Now())
	if allowed { flow.active = true }
	h.mu.Unlock()
	if !allowed { N.CloseOnHandshakeFailure(flow, finish, errLease); return }
	if err := flow.SetReadDeadline(time.Time{}); err != nil {
		N.CloseOnHandshakeFailure(flow, finish, errLease)
		return
	}
	metadata.DestinationAddresses = nil
	metadata.Destination = M.Socksaddr{Fqdn: serverName, Port: 443}
	metadata.TLSFragment, metadata.TLSRecordFragment = false, false
	h.connection.NewConnection(flowCtx, &connectedDialer{conn: &leaseRemote{Conn: remote, flow: flow}},
		&cachedLeaseConn{CachedConn: bufio.NewCachedConn(flow, buf.As(raw)), flow: flow}, metadata, finish)
}

type cachedLeaseConn struct { *bufio.CachedConn; flow *leaseFlow }
func (c *cachedLeaseConn) CloseWrite() error {
	if !c.flow.current() { return errLease }
	if closer, ok := c.flow.Conn.(N.WriteCloser); ok { return closer.CloseWrite() }
	return c.flow.Close()
}

type connectedDialer struct { conn net.Conn; taken atomic.Bool }
func (d *connectedDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	if d.taken.Swap(true) { return nil, errScope }
	return d.conn, nil
}
func (d *connectedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) { return nil, errScope }

type leaseFlow struct {
	net.Conn
	owner *Outbound
	authorization *leaseAuthorization
	cancel context.CancelFunc
	mu sync.Mutex
	remote net.Conn
	closed bool
	active bool // guarded by owner.mu; the transport passed final admission
	timer *time.Timer
}
func (c *leaseFlow) setRemote(remote net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed { return false }
	c.remote = remote
	return true
}
func (c *leaseFlow) Close() error {
	c.mu.Lock()
	if c.closed { c.mu.Unlock(); return nil }
	c.closed = true
	if c.timer != nil { c.timer.Stop() }
	remote := c.remote
	c.mu.Unlock()
	c.cancel()
	err := c.Conn.Close()
	if remote != nil { _ = remote.Close() }
	c.owner.mu.Lock()
	delete(c.owner.flows, c)
	c.owner.mu.Unlock()
	return err
}
func (c *leaseFlow) current() bool {
	now := time.Now()
	if now.Before(c.authorization.issued) || !now.Before(c.authorization.activeUntil) || !now.Before(c.authorization.activeDeadline) {
		_ = c.Close()
		return false
	}
	c.owner.mu.Lock()
	terminated := c.owner.terminateActive || c.authorization.terminateActive
	c.owner.mu.Unlock()
	if terminated { return false }
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed
}
func (c *leaseFlow) Read(p []byte) (int, error) {
	if !c.current() { return 0, errLease }
	n, err := c.Conn.Read(p)
	if !c.current() { return 0, errLease }
	return n, err
}
func (c *leaseFlow) Write(p []byte) (int, error) {
	if !c.current() { return 0, errLease }
	return c.Conn.Write(p)
}

// Wrap the relay too: the connection manager may write the cached ClientHello
// without reading the source again. Neither copy direction may unwrap this fence.
type leaseRemote struct { net.Conn; flow *leaseFlow }
func (c *leaseRemote) Read(p []byte) (int, error) {
	if !c.flow.current() { return 0, errLease }
	n, err := c.Conn.Read(p)
	if !c.flow.current() { return 0, errLease }
	return n, err
}
func (c *leaseRemote) Write(p []byte) (int, error) {
	if !c.flow.current() { return 0, errLease }
	return c.Conn.Write(p)
}
func (c *leaseRemote) CloseWrite() error {
	if !c.flow.current() { return errLease }
	if closer, ok := c.Conn.(N.WriteCloser); ok { return closer.CloseWrite() }
	return c.Conn.Close()
}

func normalizeDomain(value string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(name) == 0 || len(name) > 253 || name == "pokrov.space" || strings.HasSuffix(name, ".pokrov.space") { return "", errScope }
	if _, err := netip.ParseAddr(name); err == nil { return "", errScope }
	labels := strings.Split(name, ".")
	if len(labels) < 2 { return "", errScope }
	for _, label := range labels { if !domainLabelPattern.MatchString(label) { return "", errScope } }
	return name, nil
}

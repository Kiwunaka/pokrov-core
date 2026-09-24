package atslease

import (
	"context"
	"errors"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const Type = "pokrov-ats-lease"
const timeLayout = "2006-01-02T15:04:05Z"

var errLease = errors.New("ats_endpoint_lease_unavailable")
var leaseIDPattern = regexp.MustCompile(`^lease_[a-f0-9]{32}$`)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PokrovATSLeaseOutboundOptions](registry, Type, NewOutbound)
}

// A single profile's upstream is reachable through this outbound. Every TCP
// and UDP flow retains the original active deadline, even after new admission
// stops. A revoked lease stays registered as a rejecting route target.
type Outbound struct {
	outbound.Adapter
	manager adapter.OutboundManager
	upstreamTag string
	leaseID string
	upstream adapter.Outbound
	issued, newUntil, activeUntil time.Time
	newDeadline, activeDeadline time.Time
	mu sync.Mutex
	closed, revoked, terminateActive bool
	flows map[*leaseFlow]struct{}
}

type leaseFlow struct {
	owner *Outbound
	cancel context.CancelFunc
	connection net.Conn
	packet net.PacketConn
	timer *time.Timer
	closed bool // guarded by owner.mu
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timeLayout, value)
	if err != nil || parsed.Year() < 1 || parsed.Format(timeLayout) != value {
		return time.Time{}, errLease
	}
	return parsed, nil
}

func NewOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string,
	options option.PokrovATSLeaseOutboundOptions) (adapter.Outbound, error) {
	issued, err := parseTime(options.IssuedAt)
	if err != nil { return nil, err }
	newUntil, err := parseTime(options.NewFlowsUntil)
	if err != nil { return nil, err }
	activeUntil, err := parseTime(options.ActiveFlowsUntil)
	if err != nil { return nil, err }
	now := time.Now()
	if tag == "" || options.UpstreamTag == "" || options.UpstreamTag == tag ||
		!leaseIDPattern.MatchString(options.LeaseID) || now.Before(issued) ||
		!now.Before(newUntil) || !newUntil.After(issued) || activeUntil.Before(newUntil) ||
		newUntil.Sub(issued) > 10*time.Minute || activeUntil.Sub(issued) > time.Hour {
		return nil, errLease
	}
	manager := service.FromContext[adapter.OutboundManager](ctx)
	if manager == nil { return nil, errLease }
	return &Outbound{
		Adapter: outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{options.UpstreamTag}),
		manager: manager, upstreamTag: options.UpstreamTag,
		leaseID: options.LeaseID,
		issued: issued, newUntil: newUntil, activeUntil: activeUntil,
		newDeadline: now.Add(newUntil.Sub(now)), activeDeadline: now.Add(activeUntil.Sub(now)),
		flows: make(map[*leaseFlow]struct{}),
	}, nil
}

// Confirm the exact loaded gate for a host handoff. This neither grants a
// lease nor changes flow deadlines; it only attests current Core ownership.
func (h *Outbound) ConfirmLease(leaseID, issuedAt, newFlowsUntil, activeFlowsUntil string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	return h.upstream != nil && h.admits(now) && now.Before(h.activeDeadline) &&
		h.leaseID == leaseID && h.issued.Format(timeLayout) == issuedAt &&
		h.newUntil.Format(timeLayout) == newFlowsUntil &&
		h.activeUntil.Format(timeLayout) == activeFlowsUntil
}

func (h *Outbound) Start() error {
	upstream, found := h.manager.Outbound(h.upstreamTag)
	if !found || upstream.Type() != "vless" { return errLease }
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed { return errLease }
	h.upstream = upstream
	return nil
}

func (h *Outbound) Close() error { return h.revoke(true, true) }

// The host may call this only for a received safety decision bound to the
// exact running profile/lease. Drain blocks new flows; terminate also closes
// existing ones. No later call re-enables the outbound.
func (h *Outbound) Revoke(terminateActive bool) { _ = h.revoke(false, terminateActive) }

func (h *Outbound) RevokeLease(leaseID string, terminateActive bool) bool {
	if h.leaseID != leaseID { return false }
	h.Revoke(terminateActive)
	return true
}

func (h *Outbound) revoke(closeOutbound, terminateActive bool) error {
	h.mu.Lock()
	if closeOutbound { h.closed = true }
	h.revoked = true
	if terminateActive { h.terminateActive = true }
	flows := make([]*leaseFlow, 0, len(h.flows))
	if terminateActive {
		for flow := range h.flows { flows = append(flows, flow) }
	} else {
		for flow := range h.flows {
			if flow.connection == nil && flow.packet == nil { flows = append(flows, flow) }
		}
	}
	h.mu.Unlock()
	for _, flow := range flows { _ = flow.close() }
	return nil
}

func (h *Outbound) admits(now time.Time) bool {
	return !h.closed && !h.revoked && !now.Before(h.issued) &&
		now.Before(h.newUntil) && now.Before(h.newDeadline)
}

func (h *Outbound) begin(ctx context.Context) (*leaseFlow, context.Context, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.upstream == nil || !h.admits(time.Now()) { return nil, nil, errLease }
	dialCtx, cancel := context.WithCancel(ctx)
	flow := &leaseFlow{owner: h, cancel: cancel}
	h.flows[flow] = struct{}{}
	return flow, dialCtx, nil
}

func (h *Outbound) finishDial(flow *leaseFlow, dialCtx context.Context, conn net.Conn, packet net.PacketConn) error {
	h.mu.Lock()
	now := time.Now()
	if flow.closed || dialCtx.Err() != nil || !h.admits(now) || !now.Before(h.activeUntil) || !now.Before(h.activeDeadline) {
		h.mu.Unlock()
		if conn != nil { _ = conn.Close() }
		if packet != nil { _ = packet.Close() }
		_ = flow.close()
		return errLease
	}
	flow.connection, flow.packet = conn, packet
	flow.timer = time.AfterFunc(time.Until(h.activeDeadline), func() { _ = flow.close() })
	h.mu.Unlock()
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	flow, dialCtx, err := h.begin(ctx)
	if err != nil { return nil, err }
	deadline := time.AfterFunc(time.Until(h.newDeadline), flow.cancel)
	conn, err := h.upstream.DialContext(dialCtx, network, destination)
	deadline.Stop()
	if err != nil { _ = flow.close(); return nil, err }
	if err := h.finishDial(flow, dialCtx, conn, nil); err != nil { return nil, err }
	return &leasedConn{Conn: conn, flow: flow}, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	flow, dialCtx, err := h.begin(ctx)
	if err != nil { return nil, err }
	deadline := time.AfterFunc(time.Until(h.newDeadline), flow.cancel)
	packet, err := h.upstream.ListenPacket(dialCtx, destination)
	deadline.Stop()
	if err != nil { _ = flow.close(); return nil, err }
	if err := h.finishDial(flow, dialCtx, nil, packet); err != nil { return nil, err }
	return &leasedPacket{PacketConn: packet, flow: flow}, nil
}

func (f *leaseFlow) current() bool {
	f.owner.mu.Lock()
	defer f.owner.mu.Unlock()
	now := time.Now()
	return !f.closed && !f.owner.terminateActive &&
		now.Before(f.owner.activeUntil) && now.Before(f.owner.activeDeadline)
}

func (f *leaseFlow) close() error {
	h := f.owner
	h.mu.Lock()
	if f.closed { h.mu.Unlock(); return nil }
	f.closed = true
	delete(h.flows, f)
	timer, cancel, conn, packet := f.timer, f.cancel, f.connection, f.packet
	h.mu.Unlock()
	if timer != nil { timer.Stop() }
	cancel()
	if conn != nil { return conn.Close() }
	if packet != nil { return packet.Close() }
	return nil
}

type leasedConn struct { net.Conn; flow *leaseFlow }
func (c *leasedConn) Read(p []byte) (int, error) {
	if !c.flow.current() { _ = c.flow.close(); return 0, errLease }
	n, err := c.Conn.Read(p)
	if !c.flow.current() { _ = c.flow.close(); return 0, errLease }
	return n, err
}
func (c *leasedConn) Write(p []byte) (int, error) {
	if !c.flow.current() { _ = c.flow.close(); return 0, errLease }
	return c.Conn.Write(p)
}
func (c *leasedConn) CloseWrite() error {
	if !c.flow.current() { _ = c.flow.close(); return errLease }
	if closer, ok := c.Conn.(N.WriteCloser); ok { return closer.CloseWrite() }
	return c.flow.close()
}
func (c *leasedConn) Close() error { return c.flow.close() }

type leasedPacket struct { net.PacketConn; flow *leaseFlow }
func (c *leasedPacket) ReadFrom(p []byte) (int, net.Addr, error) {
	if !c.flow.current() { _ = c.flow.close(); return 0, nil, errLease }
	n, addr, err := c.PacketConn.ReadFrom(p)
	if !c.flow.current() { _ = c.flow.close(); return 0, nil, errLease }
	return n, addr, err
}
func (c *leasedPacket) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !c.flow.current() { _ = c.flow.close(); return 0, errLease }
	return c.PacketConn.WriteTo(p, addr)
}
func (c *leasedPacket) Close() error { return c.flow.close() }

package localdpi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/pokrov/atslease"
	"github.com/sagernet/sing-box/protocol/pokrov/dnstt"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
)

const Type = "pokrov-local-dpi"
const setupTimeout = 5 * time.Second

const (
	admissionUnpublished uint32 = iota
	admissionReady
	admissionFailed
	admissionWithdrawn
)

var errScope = errors.New("local_dpi_scope_invalid")
var errClosed = errors.New("local_dpi_closed")
var errUnavailable = errors.New("local_dpi_admission_unavailable")

type admissionFailure string

const (
	failureConnectTimeoutIPv4 admissionFailure = "connect_timeout_ipv4"
	failureConnectTimeoutIPv6 admissionFailure = "connect_timeout_ipv6"
	failureConnectErrorIPv4   admissionFailure = "connect_error_ipv4"
	failureConnectErrorIPv6   admissionFailure = "connect_error_ipv6"
	failureEarlyRead          admissionFailure = "early_read"
	failureEarlyWrite         admissionFailure = "early_write"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PokrovLocalDPIOutboundOptions](registry, Type, NewOutbound)
}

var _ adapter.ConnectionHandler = (*Outbound)(nil)
var _ adapter.PacketConnectionHandler = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	manager           adapter.OutboundManager
	connection        adapter.ConnectionManager
	proxy             N.Dialer
	vpnTag            string
	vpn               adapter.Outbound
	serviceID         string
	preferTCP         bool
	admissionID       string
	admission         atomic.Uint32
	admissionResolved chan struct{}
	admissionDeadline time.Time
	withdrawCtx       context.Context
	withdrawCancel    context.CancelFunc
	mu                sync.Mutex
	closed            bool
	flows             map[*flow]struct{}
	withdrawCompleted bool
	localHandoffs     uint64
	vpnHandoffs       uint64
	quicRejected      uint64
	failureReason     admissionFailure // First ready-to-failed cause; guarded by mu.
}

type Observation struct {
	State             string `json:"state"`
	WithdrawCompleted bool   `json:"withdraw_completed"`
	LocalHandoffs     uint64 `json:"local_handoffs"`
	VPNHandoffs       uint64 `json:"vpn_handoffs"`
	QUICRejected      uint64 `json:"quic_rejected"`
	FailureReason     string `json:"failure_reason"`
}

func NewOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string,
	options option.PokrovLocalDPIOutboundOptions) (adapter.Outbound, error) {
	if tag == "" ||
		options.ServiceID == "" || options.VPNOutbound == "" || options.VPNOutbound == tag || options.Detour != "" ||
		(options.PreferTCP && options.ServiceID != "youtube") {
		return nil, errScope
	}
	var server netip.Addr
	if options.WindowsDirect {
		if runtime.GOOS != "windows" || options.BindInterface == "" || options.Server != "" || options.ServerPort != 0 {
			return nil, errScope
		}
	} else {
		var err error
		server, err = netip.ParseAddr(options.Server)
		if err != nil || !server.IsLoopback() || options.ServerPort == 0 {
			return nil, errScope
		}
	}
	manager := service.FromContext[adapter.OutboundManager](ctx)
	connection := service.FromContext[adapter.ConnectionManager](ctx)
	if manager == nil || connection == nil {
		return nil, errScope
	}
	transport, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx, Options: options.DialerOptions, ProtectPlatformSocket: true,
	})
	if err != nil {
		return nil, err
	}
	var proxy N.Dialer = transport
	if !options.WindowsDirect {
		proxy = socks.NewClient(transport, M.Socksaddr{Addr: server, Port: options.ServerPort}, socks.Version5, "", "")
	}
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, err
	}
	withdrawCtx, withdrawCancel := context.WithCancel(ctx)
	return &Outbound{
		Adapter: outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{options.VPNOutbound}),
		manager: manager, connection: connection,
		proxy:  proxy,
		vpnTag: options.VPNOutbound, serviceID: options.ServiceID, preferTCP: options.PreferTCP, admissionID: hex.EncodeToString(identity[:]),
		admissionResolved: make(chan struct{}), withdrawCtx: withdrawCtx, withdrawCancel: withdrawCancel, flows: make(map[*flow]struct{}),
	}, nil
}

func (h *Outbound) AdmissionID() string { return h.admissionID }
func (h *Outbound) ServiceID() string   { return h.serviceID }
func (h *Outbound) IsReady() bool       { return h.admission.Load() == admissionReady }

func (h *Outbound) ReadObservation() Observation {
	h.mu.Lock()
	defer h.mu.Unlock()
	states := [...]string{"unpublished", "ready", "failed", "withdrawn"}
	reason := string(h.failureReason)
	if reason == "" {
		reason = "none"
	}
	return Observation{
		State: states[h.admission.Load()], WithdrawCompleted: h.withdrawCompleted,
		LocalHandoffs: h.localHandoffs, VPNHandoffs: h.vpnHandoffs, QUICRejected: h.quicRejected, FailureReason: reason,
	}
}

func (h *Outbound) failAdmission(reason admissionFailure) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.admission.CompareAndSwap(admissionReady, admissionFailed) {
		h.failureReason = reason
	}
}

// Only the trusted native publisher may admit the freshly constructed runtime
// after its proof. A failed or withdrawn admission cannot be reopened.
func (h *Outbound) AdmitAdmission(expectedID string) bool {
	h.mu.Lock()
	if h.closed || expectedID != h.admissionID || !h.admission.CompareAndSwap(admissionUnpublished, admissionReady) {
		h.mu.Unlock()
		return false
	}
	close(h.admissionResolved)
	h.mu.Unlock()
	return true
}

func (h *Outbound) WithdrawAdmission(expectedID string) bool {
	h.mu.Lock()
	if expectedID != h.admissionID {
		h.mu.Unlock()
		return false
	}
	previous := h.admission.Swap(admissionWithdrawn)
	if previous == admissionWithdrawn {
		h.mu.Unlock()
		return false
	}
	if previous == admissionUnpublished {
		close(h.admissionResolved)
	}
	flows := make([]*flow, 0, len(h.flows))
	for f := range h.flows {
		if f.local {
			flows = append(flows, f)
		}
	}
	h.mu.Unlock()
	// Deny before the native owner stops its filter or SOCKS child. Close only
	// offloaded streams; ordinary VPN streams remain owned by the runtime.
	h.withdrawCancel()
	for _, f := range flows {
		h.mu.Lock()
		if f.local {
			f.close()
		}
		h.mu.Unlock()
	}
	h.mu.Lock()
	h.withdrawCompleted = true
	h.mu.Unlock()
	return true
}

func (h *Outbound) Start() error {
	vpn, found := h.manager.Outbound(h.vpnTag)
	if !found || !protectedFallback(h.manager, vpn, make(map[string]bool)) {
		return errScope
	}
	h.vpn = vpn
	h.mu.Lock()
	if h.admissionDeadline.IsZero() {
		h.admissionDeadline = time.Now().Add(setupTimeout)
	}
	h.mu.Unlock()
	return nil
}

func protectedFallback(manager adapter.OutboundManager, target adapter.Outbound, seen map[string]bool) bool {
	if seen[target.Tag()] {
		return false
	}
	seen[target.Tag()] = true
	defer delete(seen, target.Tag())
	switch target.Type() {
	case C.TypeNaive:
		protected, ok := target.(interface{ IsProtectedH2() bool })
		return ok && protected.IsProtectedH2()
	case C.TypeVLESS, C.TypeHysteria2, C.TypeWireGuard, C.TypeAwg:
		// A protected exit can itself use an encrypted bridge detour.
	case C.TypeSelector, C.TypeURLTest, atslease.Type:
		if len(target.Dependencies()) == 0 {
			return false
		}
	default:
		return false
	}
	for _, tag := range target.Dependencies() {
		child, found := manager.Outbound(tag)
		// The native preparation checks the exact VLESS/DNSTT options. Here
		// require the constructed carrier as that leaf's dependency; a group
		// containing a standalone raw DNSTT transport remains forbidden.
		if found && target.Type() == C.TypeVLESS {
			if _, valid := child.(*dnstt.Outbound); valid {
				continue
			}
		}
		if !found || !protectedFallback(manager, child, seen) {
			return false
		}
	}
	return true
}

func (h *Outbound) Close() error {
	h.mu.Lock()
	h.closed = true
	flows := make([]*flow, 0, len(h.flows))
	for f := range h.flows {
		flows = append(flows, f)
	}
	h.mu.Unlock()
	h.WithdrawAdmission(h.admissionID)
	for _, f := range flows {
		f.close()
	}
	return nil
}

// Raw dialers and UDP never authorize local offload.
func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return h.vpn.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return h.vpn.ListenPacket(ctx, destination)
}

// Wait only for the current YouTube holder, with one deadline shared by all
// flows. Withdrawal resumes the protected VPN fallback; runtime cancellation
// or closure must not start a fallback connection.
func (h *Outbound) waitYouTubeAdmission(ctx context.Context) error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return errClosed
	}
	waiting := h.serviceID == "youtube" && h.preferTCP && h.admission.Load() == admissionUnpublished
	deadline := h.admissionDeadline
	h.mu.Unlock()
	if waiting && time.Until(deadline) > 0 {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-h.admissionResolved:
		case <-h.withdrawCtx.Done():
		case <-ctx.Done():
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || (h.withdrawCtx.Err() != nil && h.admission.Load() != admissionWithdrawn) {
		return errClosed
	}
	return nil
}

// Only routed, signed YouTube traffic can prefer TCP. Raw dialers keep their
// VPN behavior, and unavailable admissions never deny the ordinary UDP path.
func (h *Outbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	preferTCP := h.preferTCP && h.serviceID == "youtube" && metadata.Destination.Port == 443
	if preferTCP {
		if err := h.waitYouTubeAdmission(ctx); err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
	}
	h.mu.Lock()
	closed := h.closed
	reject := !closed && preferTCP && h.IsReady()
	if reject {
		h.quicRejected++
	}
	h.mu.Unlock()
	if closed {
		N.CloseOnHandshakeFailure(conn, onClose, errClosed)
		return
	}
	if reject {
		N.CloseOnHandshakeFailure(conn, onClose, syscall.ECONNREFUSED)
		return
	}
	h.connection.NewPacketConnection(ctx, h.vpn, conn, metadata, onClose)
}

func (h *Outbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		N.CloseOnHandshakeFailure(conn, onClose, errClosed)
		return
	}
	flowCtx, cancel := context.WithCancel(ctx)
	eligible := metadata.Network == N.NetworkTCP && metadata.Destination.Port == 443 && metadata.Destination.Addr.IsGlobalUnicast() &&
		!metadata.Destination.Addr.IsPrivate() && !metadata.Destination.Addr.Is4In6()
	f := &flow{client: conn, cancel: cancel, local: eligible && h.IsReady()}
	h.flows[f] = struct{}{}
	local := f.local
	h.mu.Unlock()
	stopCancel := context.AfterFunc(flowCtx, f.close)
	finish := N.OnceClose(func(err error) {
		stopCancel()
		f.close()
		h.mu.Lock()
		delete(h.flows, f)
		h.mu.Unlock()
		if onClose != nil {
			onClose(err)
		}
	})
	if flowCtx.Err() != nil {
		N.CloseOnHandshakeFailure(conn, finish, flowCtx.Err())
		return
	}
	if eligible && h.preferTCP && h.serviceID == "youtube" {
		if err := h.waitYouTubeAdmission(flowCtx); err != nil {
			N.CloseOnHandshakeFailure(conn, finish, err)
			return
		}
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			N.CloseOnHandshakeFailure(conn, finish, errClosed)
			return
		}
		f.local = h.IsReady()
		local = f.local
		h.mu.Unlock()
	}
	if !local {
		h.connectVPN(flowCtx, f, metadata, finish)
		return
	}
	setupCtx, stopSetup := context.WithTimeout(flowCtx, setupTimeout)
	stopWithdraw := context.AfterFunc(h.withdrawCtx, stopSetup)
	remote, err := h.proxy.DialContext(setupCtx, N.NetworkTCP, metadata.Destination)
	setupErr := setupCtx.Err()
	stopWithdraw()
	stopSetup()
	if flowCtx.Err() != nil || h.withdrawCtx.Err() != nil || errors.Is(err, context.Canceled) {
		if remote != nil {
			_ = remote.Close()
		}
		N.CloseOnHandshakeFailure(conn, finish, errUnavailable)
		return
	}
	// Exhausting our setup budget while the caller's flow is still alive is
	// a transport failure. A late socket is closed before the one VPN fallback.
	if err != nil || errors.Is(setupErr, context.DeadlineExceeded) {
		if remote != nil {
			_ = remote.Close()
		}
		var timeoutError net.Error
		timedOut := errors.Is(setupErr, context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) ||
			(errors.As(err, &timeoutError) && timeoutError.Timeout())
		reason := failureConnectErrorIPv6
		if metadata.Destination.Addr.Is4() {
			reason = failureConnectErrorIPv4
		}
		if timedOut {
			reason = failureConnectTimeoutIPv6
			if metadata.Destination.Addr.Is4() {
				reason = failureConnectTimeoutIPv4
			}
		}
		h.failAdmission(reason)
		if h.admission.Load() == admissionWithdrawn {
			N.CloseOnHandshakeFailure(conn, finish, errUnavailable)
			return
		}
		h.connectVPN(flowCtx, f, metadata, finish)
		return
	}
	// SOCKS CONNECT and direct TCP setup contain no client payload. After handoff,
	// every write (including a partial write) belongs to it; no retry exists.
	observed := &observedConn{Conn: remote, ctx: flowCtx, owner: h}
	h.mu.Lock()
	attached := !h.closed && h.IsReady() && flowCtx.Err() == nil && f.attach(observed)
	if attached {
		h.localHandoffs++
	}
	h.mu.Unlock()
	if !attached {
		_ = observed.Close()
		N.CloseOnHandshakeFailure(conn, finish, errUnavailable)
		return
	}
	metadata.DestinationAddresses = nil
	h.connection.NewConnection(flowCtx, &connectedDialer{observed}, conn, metadata, finish)
}

func (h *Outbound) connectVPN(ctx context.Context, f *flow, metadata adapter.InboundContext, finish N.CloseHandlerFunc) {
	h.mu.Lock()
	f.local = false
	h.mu.Unlock()
	if ctx.Err() != nil {
		N.CloseOnHandshakeFailure(f.client, finish, ctx.Err())
		return
	}
	// One logical VPN dial, regardless of the router's resolved address list.
	remote, err := h.vpn.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		N.CloseOnHandshakeFailure(f.client, finish, err)
		return
	}
	if !f.attach(remote) {
		N.CloseOnHandshakeFailure(f.client, finish, errUnavailable)
		return
	}
	h.mu.Lock()
	h.vpnHandoffs++
	h.mu.Unlock()
	metadata.DestinationAddresses = nil
	h.connection.NewConnection(ctx, &connectedDialer{remote}, f.client, metadata, finish)
}

type connectedDialer struct{ conn net.Conn }

func (d *connectedDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}
func (d *connectedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errScope
}

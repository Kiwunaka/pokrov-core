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
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
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

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PokrovLocalDPIOutboundOptions](registry, Type, NewOutbound)
}

var _ adapter.ConnectionHandler = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	manager        adapter.OutboundManager
	connection     adapter.ConnectionManager
	proxy          N.Dialer
	vpnTag         string
	vpn            adapter.Outbound
	serviceID      string
	admissionID    string
	admission      atomic.Uint32
	withdrawCtx    context.Context
	withdrawCancel context.CancelFunc
	mu             sync.Mutex
	closed         bool
	flows          map[*flow]struct{}
}

func NewOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string,
	options option.PokrovLocalDPIOutboundOptions) (adapter.Outbound, error) {
	if tag == "" ||
		options.ServiceID == "" || options.VPNOutbound == "" || options.VPNOutbound == tag || options.Detour != "" {
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
		vpnTag: options.VPNOutbound, serviceID: options.ServiceID, admissionID: hex.EncodeToString(identity[:]),
		withdrawCtx: withdrawCtx, withdrawCancel: withdrawCancel, flows: make(map[*flow]struct{}),
	}, nil
}

func (h *Outbound) AdmissionID() string { return h.admissionID }
func (h *Outbound) ServiceID() string   { return h.serviceID }
func (h *Outbound) IsReady() bool       { return h.admission.Load() == admissionReady }

// Only the trusted native publisher may admit the freshly constructed runtime
// after its proof. A failed or withdrawn admission cannot be reopened.
func (h *Outbound) AdmitAdmission(expectedID string) bool {
	return expectedID == h.admissionID && h.admission.CompareAndSwap(admissionUnpublished, admissionReady)
}

func (h *Outbound) WithdrawAdmission(expectedID string) bool {
	if expectedID != h.admissionID || h.admission.Swap(admissionWithdrawn) == admissionWithdrawn {
		return false
	}
	// Pending CONNECTs stop, while established streams are never replayed.
	h.withdrawCancel()
	return true
}

func (h *Outbound) Start() error {
	vpn, found := h.manager.Outbound(h.vpnTag)
	if !found || !protectedFallback(h.manager, vpn, make(map[string]bool)) {
		return errScope
	}
	h.vpn = vpn
	return nil
}

func protectedFallback(manager adapter.OutboundManager, target adapter.Outbound, seen map[string]bool) bool {
	if seen[target.Tag()] {
		return false
	}
	seen[target.Tag()] = true
	defer delete(seen, target.Tag())
	switch target.Type() {
	case C.TypeVLESS, C.TypeHysteria2, C.TypeWireGuard, C.TypeAwg:
		return true
	case C.TypeSelector, C.TypeURLTest:
		if len(target.Dependencies()) == 0 {
			return false
		}
		for _, tag := range target.Dependencies() {
			child, found := manager.Outbound(tag)
			if !found || !protectedFallback(manager, child, seen) {
				return false
			}
		}
		return true
	default:
		return false
	}
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

func (h *Outbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		N.CloseOnHandshakeFailure(conn, onClose, errClosed)
		return
	}
	flowCtx, cancel := context.WithCancel(ctx)
	f := &flow{client: conn, cancel: cancel}
	h.flows[f] = struct{}{}
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
	eligible := metadata.Network == N.NetworkTCP && metadata.Destination.Port == 443 && metadata.Destination.Addr.IsGlobalUnicast() &&
		!metadata.Destination.Addr.IsPrivate() && !metadata.Destination.Addr.Is4In6()
	if !eligible || !h.IsReady() {
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
		h.admission.CompareAndSwap(admissionReady, admissionFailed)
		if h.admission.Load() == admissionWithdrawn {
			N.CloseOnHandshakeFailure(conn, finish, errUnavailable)
			return
		}
		h.connectVPN(flowCtx, f, metadata, finish)
		return
	}
	// SOCKS CONNECT and direct TCP setup contain no client payload. After handoff,
	// every write (including a partial write) belongs to it; no retry exists.
	observed := &observedConn{Conn: remote, ctx: flowCtx, admission: &h.admission}
	if !f.attach(observed) {
		N.CloseOnHandshakeFailure(conn, finish, errUnavailable)
		return
	}
	metadata.DestinationAddresses = nil
	h.connection.NewConnection(flowCtx, &connectedDialer{observed}, conn, metadata, finish)
}

func (h *Outbound) connectVPN(ctx context.Context, f *flow, metadata adapter.InboundContext, finish N.CloseHandlerFunc) {
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

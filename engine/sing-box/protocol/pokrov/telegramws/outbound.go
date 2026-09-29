package telegramws

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const Type = "pokrov-telegram-ws"
const setupTimeout = 5 * time.Second

var errScope = errors.New("telegram_ws_scope_invalid")
var errClosed = errors.New("telegram_ws_closed")

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PokrovTelegramWSOutboundOptions](registry, Type, NewOutbound)
}

var _ adapter.ConnectionHandler = (*Outbound)(nil)

type datacenter struct {
	host        string
	address     M.Socksaddr
	unavailable bool // guarded by Outbound.mu, reset only by a new runtime
}

type Outbound struct {
	outbound.Adapter
	manager    adapter.OutboundManager
	connection adapter.ConnectionManager
	logger     log.ContextLogger
	dialer     N.Dialer
	vpnTag     string
	vpn        adapter.Outbound
	addresses  map[netip.Addr]*datacenter
	mu         sync.Mutex
	closed     bool
	flows      map[net.Conn]context.CancelFunc
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string,
	options option.PokrovTelegramWSOutboundOptions) (adapter.Outbound, error) {
	if tag == "" || options.VPNOutbound == "" || options.VPNOutbound == tag || options.Detour != "" ||
		len(options.Datacenters) == 0 {
		return nil, errScope
	}
	addresses := make(map[netip.Addr]*datacenter)
	seenDC := make(map[int]bool)
	for _, dc := range options.Datacenters {
		gateway, err := netip.ParseAddr(dc.WebsocketAddress)
		if dc.ID < 1 || dc.ID > 5 || seenDC[dc.ID] || err != nil || !publicAddress(gateway) || len(dc.Addresses) == 0 {
			return nil, errScope
		}
		seenDC[dc.ID] = true
		path := &datacenter{host: "kws" + strconv.Itoa(dc.ID) + ".web.telegram.org",
			address: M.Socksaddr{Addr: gateway, Port: 443}}
		for _, value := range dc.Addresses {
			address, err := netip.ParseAddr(value)
			if err != nil || !publicAddress(address) || addresses[address] != nil {
				return nil, errScope
			}
			addresses[address] = path
		}
	}
	transport, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx, Options: options.DialerOptions, ProtectPlatformSocket: true,
	})
	if err != nil {
		return nil, err
	}
	manager := service.FromContext[adapter.OutboundManager](ctx)
	connection := service.FromContext[adapter.ConnectionManager](ctx)
	if manager == nil || connection == nil {
		return nil, errScope
	}
	return &Outbound{
		Adapter: outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{options.VPNOutbound}),
		manager: manager, connection: connection, logger: logger, dialer: transport,
		vpnTag: options.VPNOutbound, addresses: addresses, flows: make(map[net.Conn]context.CancelFunc),
	}, nil
}

func publicAddress(address netip.Addr) bool {
	return address.IsGlobalUnicast() && !address.IsPrivate() && !address.Is4In6()
}

func (h *Outbound) Start() error {
	vpn, found := h.manager.Outbound(h.vpnTag)
	if !found || !protectedFallback(h.manager, vpn, make(map[string]bool)) {
		return errScope
	}
	h.vpn = vpn
	return nil
}

// A selector must not acquire a Direct fallback after the host changes its
// selected candidate. Only the existing encrypted POKROV transport families
// and groups made entirely from them can serve this boundary fallback.
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
	flows := make(map[net.Conn]context.CancelFunc, len(h.flows))
	for conn, cancel := range h.flows {
		flows[conn] = cancel
	}
	h.mu.Unlock()
	for conn, cancel := range flows {
		cancel()
		_ = conn.Close()
	}
	return nil
}

// A direct dial without the native initialization cannot authorize offload.
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
	h.flows[conn] = cancel
	dc := h.addresses[metadata.Destination.Addr]
	available := dc != nil && !dc.unavailable && metadata.Destination.Port == 443
	h.mu.Unlock()
	stopCancel := context.AfterFunc(flowCtx, func() { _ = conn.Close() })
	finish := N.OnceClose(func(err error) {
		stopCancel()
		cancel()
		_ = conn.Close()
		h.mu.Lock()
		delete(h.flows, conn)
		h.mu.Unlock()
		if onClose != nil {
			onClose(err)
		}
	})
	if !available {
		h.connection.NewConnection(flowCtx, h.vpn, conn, metadata, finish)
		return
	}
	deadline := time.Now().Add(setupTimeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		N.CloseOnHandshakeFailure(conn, finish, err)
		return
	}
	initial := make([]byte, 64)
	n, readErr := io.ReadFull(conn, initial)
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		N.CloseOnHandshakeFailure(conn, finish, err)
		return
	}
	initial = initial[:n]
	client := bufio.NewCachedConn(conn, buf.As(initial))
	if readErr != nil || !nativeObfuscatedInitialization(initial) {
		h.connection.NewConnection(flowCtx, h.vpn, client, metadata, finish)
		return
	}
	setupCtx, stopSetup := context.WithDeadline(flowCtx, deadline)
	remote, err := h.connectGateway(setupCtx, dc)
	stopSetup()
	if err != nil {
		if flowCtx.Err() == nil {
			h.markUnavailable(dc)
		}
		h.connection.NewConnection(flowCtx, h.vpn, client, metadata, finish)
		return
	}
	// Once any MTProto bytes have reached WSS this stream must never be replayed
	// into another transport. A failed stream closes; the next one uses VPN.
	metadata.DestinationAddresses = nil
	metadata.TLSFragment, metadata.TLSRecordFragment = false, false
	metadata.TLSSpoof = ""
	h.connection.NewConnection(flowCtx, &connectedDialer{conn: remote}, client, metadata,
		finish)
}

func (h *Outbound) markUnavailable(dc *datacenter) {
	h.mu.Lock()
	dc.unavailable = true
	h.mu.Unlock()
}

type connectedDialer struct{ conn net.Conn }

func (d *connectedDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}
func (d *connectedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errScope
}

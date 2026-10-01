package telegramws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type datacenter struct {
	host        string
	address     M.Socksaddr
	unavailable bool // guarded by Outbound.mu, reset only by a new runtime
}

type Outbound struct {
	outbound.Adapter
	manager                   adapter.OutboundManager
	connection                adapter.ConnectionManager
	logger                    log.ContextLogger
	dialer                    N.Dialer
	vpnTag                    string
	vpn                       adapter.Outbound
	addresses                 map[netip.Addr]*datacenter
	mu                        sync.Mutex
	closed                    bool
	flows                     map[*telegramFlow]struct{}
	serviceID, admissionID    string
	issued, expires, deadline time.Time
	admitted, withdrawn       bool
	withdrawCtx               context.Context
	withdrawCancel            context.CancelFunc
	expiryTimer               *time.Timer
	preparedOptions           option.PokrovTelegramWSOutboundOptions
	startContext              context.Context
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string,
	options option.PokrovTelegramWSOutboundOptions) (adapter.Outbound, error) {
	if tag == "" || options.VPNOutbound == "" || options.VPNOutbound == tag || options.Detour != "" ||
		len(options.Datacenters) == 0 || len(options.Datacenters) > 5 || tag != "pokrov-telegram-ws-"+options.ServiceID {
		return nil, errScope
	}
	deadline, verified := peekPreparation(options)
	if !verified {
		return nil, errScope
	}
	addresses := make(map[netip.Addr]*datacenter)
	seenDC := make(map[int]bool)
	for _, dc := range options.Datacenters {
		gateway, err := netip.ParseAddr(dc.WebsocketAddress)
		if dc.ID < 1 || dc.ID > 5 || seenDC[dc.ID] || err != nil || !publicAddress(gateway) || gateway.String() != dc.WebsocketAddress || len(dc.Addresses) == 0 || len(dc.Addresses) > 16 {
			return nil, errScope
		}
		seenDC[dc.ID] = true
		path := &datacenter{host: "kws" + strconv.Itoa(dc.ID) + ".web.telegram.org",
			address: M.Socksaddr{Addr: gateway, Port: 443}}
		for _, value := range dc.Addresses {
			address, err := netip.ParseAddr(value)
			if err != nil || !publicAddress(address) || address.String() != value || addresses[address] != nil {
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
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, err
	}
	issued, _ := time.Parse(time.RFC3339, options.IssuedAt)
	expires, _ := time.Parse(time.RFC3339, options.ExpiresAt)
	withdrawCtx, withdrawCancel := context.WithCancel(ctx)
	h := &Outbound{
		Adapter: outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{options.VPNOutbound}),
		manager: manager, connection: connection, logger: logger, dialer: transport,
		vpnTag: options.VPNOutbound, addresses: addresses, flows: make(map[*telegramFlow]struct{}),
		serviceID: options.ServiceID, admissionID: hex.EncodeToString(identity[:]),
		issued: issued, expires: expires, deadline: deadline, withdrawCtx: withdrawCtx, withdrawCancel: withdrawCancel,
		preparedOptions: options, startContext: ctx,
	}
	return h, nil
}

func publicAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.Is4In6() || address.Zone() != "" {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, prefix := range forbiddenPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// The same owned public-address boundary used for Smart DNS relay admission.
var forbiddenPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func PublicDatacenterAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.String() == value && publicAddress(address)
}

func (h *Outbound) Start() error {
	vpn, found := h.manager.Outbound(h.vpnTag)
	if !found || !protectedFallback(h.manager, vpn, make(map[string]bool)) {
		return errScope
	}
	h.vpn = vpn
	deadline, verified := consumePreparation(h.startContext, h.preparedOptions)
	if !verified {
		return errScope
	}
	h.mu.Lock()
	h.deadline = deadline
	h.expiryTimer = time.AfterFunc(time.Until(deadline), func() { h.WithdrawAdmission(h.admissionID) })
	h.mu.Unlock()
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
	h.WithdrawAdmission(h.admissionID)
	h.mu.Lock()
	h.closed = true
	flows := make([]*telegramFlow, 0, len(h.flows))
	for flow := range h.flows {
		flows = append(flows, flow)
	}
	h.mu.Unlock()
	for _, flow := range flows {
		flow.close()
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
	dc := h.addresses[metadata.Destination.Addr]
	current := h.currentLocked()
	var cleanup func()
	if !current {
		cleanup = h.denyLocked()
	}
	available := h.admitted && current && dc != nil && !dc.unavailable && metadata.Network == N.NetworkTCP && metadata.Destination.Port == 443
	if !available {
		h.mu.Unlock()
		if cleanup != nil {
			cleanup()
		}
		if ctx.Err() != nil {
			N.CloseOnHandshakeFailure(conn, onClose, ctx.Err())
			return
		}
		h.connection.NewConnection(ctx, h.vpn, conn, metadata, onClose)
		return
	}
	flowCtx, cancel := context.WithCancel(ctx)
	f := &telegramFlow{client: conn, ctx: flowCtx, cancel: cancel}
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
	fallback := func(client net.Conn) {
		h.mu.Lock()
		delete(h.flows, f)
		closed := h.closed
		transferred := f.transferVPN()
		h.mu.Unlock()
		if closed || !transferred || flowCtx.Err() != nil {
			N.CloseOnHandshakeFailure(client, finish, errClosed)
			return
		}
		// Ordinary VPN now owns the stream. Retain only its parent cancellation
		// hook through completion; TG expiry/revocation no longer contains it.
		h.connection.NewConnection(flowCtx, h.vpn, client, metadata, finish)
	}
	deadline := time.Now().Add(setupTimeout)
	f.mu.Lock()
	if f.setupWithdrawn {
		f.mu.Unlock()
		fallback(conn)
		return
	}
	f.reading = true
	err := conn.SetReadDeadline(deadline)
	f.mu.Unlock()
	if err != nil {
		N.CloseOnHandshakeFailure(conn, finish, err)
		return
	}
	initial := make([]byte, 64)
	n, readErr := io.ReadFull(conn, initial)
	f.mu.Lock()
	f.reading = false
	err = conn.SetReadDeadline(time.Time{})
	f.mu.Unlock()
	if err != nil {
		N.CloseOnHandshakeFailure(conn, finish, err)
		return
	}
	initial = initial[:n]
	client := bufio.NewCachedConn(conn, buf.As(initial))
	if readErr != nil || !h.IsReady() || !nativeObfuscatedInitialization(initial) {
		fallback(client)
		return
	}
	setupCtx, stopSetup := context.WithDeadline(flowCtx, deadline)
	stopWithdraw := context.AfterFunc(h.withdrawCtx, stopSetup)
	remote, err := h.connectGateway(setupCtx, dc)
	setupErr := setupCtx.Err()
	stopWithdraw()
	stopSetup()
	h.mu.Lock()
	windowCurrent := h.currentLocked()
	cleanup = nil
	if !windowCurrent {
		cleanup = h.denyLocked()
	}
	current = h.admitted && windowCurrent && flowCtx.Err() == nil && setupErr == nil && err == nil
	if current {
		current = f.attach(remote)
	}
	h.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
	if !current {
		if remote != nil {
			_ = remote.Close()
		}
		if flowCtx.Err() == nil && h.IsReady() {
			h.markUnavailable(dc)
		}
		fallback(client)
		return
	}
	// Once any MTProto bytes have reached WSS this stream must never be replayed
	// into another transport. A failed stream closes; the next one uses VPN.
	metadata.DestinationAddresses = nil
	metadata.TLSFragment, metadata.TLSRecordFragment = false, false
	metadata.TLSSpoof = ""
	h.connection.NewConnection(flowCtx, &connectedDialer{conn: &admittedConn{Conn: remote, owner: h, flow: f}}, client, metadata,
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

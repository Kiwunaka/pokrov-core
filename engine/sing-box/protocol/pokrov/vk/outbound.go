// The VK TURN wire protocol is adapted from cacggghp/vk-turn-proxy v1.8.3.
// See LICENSE and THIRD_PARTY_NOTICES.md.
package vk

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.VkOptions](registry, "vk", NewOutbound)
}

// Outbound carries a byte stream to the server's fixed upstream. Its caller
// must authenticate that server with the inner VLESS REALITY/TLS connection.
type Outbound struct {
	outbound.Adapter
	ctx              context.Context
	cancel           context.CancelFunc
	dialer           N.Dialer
	solver           CaptchaSolver
	call             string
	peer             *net.UDPAddr
	timeout          time.Duration
	gate             chan struct{}
	session          *tunnelSession
	credentialsCache *turnCredentials
}

var callPath = regexp.MustCompile(`^/call/join/([A-Za-z0-9_-]+)$`)

func parseOptions(o option.VkOptions) (string, *net.UDPAddr, error) {
	u, err := url.Parse(o.CallURL)
	if err != nil || u.Scheme != "https" || (u.Host != "vk.ru" && u.Host != "vk.com") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", nil, errors.New("invalid VK call URL")
	}
	m := callPath.FindStringSubmatch(u.Path)
	if m == nil || o.Detour != "" {
		return "", nil, errors.New("invalid VK transport options")
	}
	ip, err := netip.ParseAddr(o.Server)
	if err != nil || !ip.Is4() || o.ServerPort == 0 {
		return "", nil, errors.New("VK relay peer requires an IPv4 address and port")
	}
	return m[1], net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, o.ServerPort)), nil
}

func NewOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.VkOptions) (adapter.Outbound, error) {
	call, peer, err := parseOptions(options)
	if err != nil {
		return nil, err
	}
	d, err := dialer.NewWithOptions(dialer.Options{Context: ctx, Options: options.DialerOptions, ProtectPlatformSocket: true, RemoteIsDomain: true})
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(options.ConnectTimeout)
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	solver := service.FromContext[CaptchaSolver](ctx)
	ctx, cancel := context.WithCancel(ctx)
	h := &Outbound{Adapter: outbound.NewAdapter("vk", tag, []string{N.NetworkTCP}, nil), ctx: ctx, cancel: cancel, dialer: d, solver: solver, call: call, peer: peer, timeout: timeout, gate: make(chan struct{}, 1)}
	h.gate <- struct{}{}
	return h, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, N.ErrUnknownNetwork
	}
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	stop := context.AfterFunc(h.ctx, cancel)
	defer stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.gate:
	}
	defer func() { h.gate <- struct{}{} }()
	if h.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if h.session != nil && h.session.mux.IsClosed() {
		h.session.Close()
		h.session = nil
	}
	if h.session == nil {
		s, err := h.connect(ctx)
		if err != nil {
			return nil, err
		}
		h.session = s
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ready := make(chan result)
	session := h.session
	go func() {
		stream, err := session.mux.OpenStream()
		select {
		case ready <- result{stream, err}:
		case <-ctx.Done():
			if stream != nil {
				stream.Close()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ready:
		if result.err != nil {
			h.session.Close()
			h.session = nil
		}
		return result.conn, result.err
	}
}

func (h *Outbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, N.ErrUnknownNetwork
}

func (h *Outbound) Close() error {
	h.cancel()
	<-h.gate
	defer func() { h.gate <- struct{}{} }()
	if h.session != nil {
		h.session.Close()
		h.session = nil
	}
	h.credentialsCache = nil
	return nil
}

package dnstt

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/mahsanet/dnstt/noise"
	"github.com/mahsanet/dnstt/turbotunnel"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DnsttOptions](registry, C.TypeDNSTT, NewOutbound)
}

// Outbound is a raw TCP transport to the DNSTT server's fixed upstream. Use it
// as a VLESS detour, not as a destination-aware proxy: Noise authenticates the
// server; the upstream VLESS listener must enforce each user's entitlement.
type Outbound struct {
	outbound.Adapter
	*tunnelConfig
	ctx      context.Context
	cancel   context.CancelFunc
	dialer   N.Dialer
	resolver M.Socksaddr
	timeout  time.Duration
	gate     chan struct{}
	session  *tunnelSession // owned under gate, including setup
}

func NewOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.DnsttOptions) (adapter.Outbound, error) {
	config, err := parseOptions(options)
	if err != nil {
		return nil, err
	}
	transportDialer, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx, Options: options.DialerOptions, ProtectPlatformSocket: true,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	timeout := time.Duration(options.ConnectTimeout)
	if timeout <= 0 {
		timeout = C.TCPConnectTimeout
	}
	h := &Outbound{
		Adapter:      outbound.NewAdapter(C.TypeDNSTT, tag, []string{N.NetworkTCP}, nil),
		tunnelConfig: config,
		ctx:          ctx, cancel: cancel, dialer: transportDialer,
		resolver: M.SocksaddrFromNetIP(config.resolver),
		timeout:  timeout, gate: make(chan struct{}, 1),
	}
	h.gate <- struct{}{}
	context.AfterFunc(ctx, func() { h.Close() })
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.session != nil && h.session.closed() {
		h.session.Close()
		h.session = nil
	}
	if h.session == nil {
		session, err := h.connect(ctx)
		if err != nil {
			return nil, err
		}
		h.session = session
	}
	// smux's OpenStream has no context API. A cancelled caller owns only its
	// pending stream; it must not kill other streams on the shared session.
	type result struct {
		stream *smux.Stream
		err    error
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
		return result.stream, result.err
	}
}

func (h *Outbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, N.ErrUnknownNetwork
}

func (h *Outbound) Close() error {
	h.cancel() // also interrupts a handshake currently holding gate
	<-h.gate
	defer func() { h.gate <- struct{}{} }()
	if h.session != nil {
		h.session.Close()
		h.session = nil
	}
	return nil
}

type tunnelSession struct {
	packet *dnsPacketConn
	kcp    *kcp.UDPSession
	noise  io.ReadWriteCloser
	mux    *smux.Session
	once   sync.Once
}

func (s *tunnelSession) closed() bool {
	select {
	case <-s.packet.done:
		return true
	default:
		return s.mux.IsClosed()
	}
}

func (s *tunnelSession) Close() {
	s.once.Do(func() {
		if s.mux != nil {
			s.mux.Close()
		}
		s.kcp.Close()
		s.packet.Close()
		// The existing Noise adapter feeds an io.Pipe. Drain its final frame
		// after KCP closes so a pending pipe writer cannot outlive the session.
		if s.noise != nil {
			io.Copy(io.Discard, s.noise)
		}
	})
}

func (h *Outbound) connect(ctx context.Context) (*tunnelSession, error) {
	udp, err := h.dialer.DialContext(ctx, N.NetworkUDP, h.resolver)
	if err != nil {
		return nil, err
	}
	packet := newDNSPacketConn(bufio.NewUnbindPacketConn(udp), h.resolver.UDPAddr(), h.server.Addr)
	conn, err := kcp.NewConn2(packet.addr, nil, 0, 0, packet)
	if err != nil {
		packet.Close()
		return nil, err
	}
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if !conn.SetMtu(h.server.MTU) {
		conn.Close()
		packet.Close()
		return nil, errors.New("invalid dnstt MTU")
	}
	session := &tunnelSession{packet: packet, kcp: conn}
	// Closing the established path also interrupts a peer that never responds
	// to the Noise handshake. Setup does not leave a background dial running.
	stop := context.AfterFunc(ctx, func() { conn.Close(); packet.Close() })
	defer stop()
	session.noise, err = noise.NewClient(conn, h.key)
	if err == nil {
		config := smux.DefaultConfig()
		config.Version = 2
		config.KeepAliveTimeout = 2 * time.Minute
		config.MaxStreamBuffer = 1 << 20
		session.mux, err = smux.Client(session.noise, config)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		session.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return session, nil
}

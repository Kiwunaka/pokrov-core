package mts

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/mahsanet/dnstt/noise"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	mtscarrier "github.com/sagernet/sing-box/protocol/pokrov/mtscarrier"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"net/url"
	"regexp"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MtsOptions](registry, "mts", NewOutbound)
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
	boardURL string
	timeout  time.Duration
	gate     chan struct{}
	session  *tunnelSession // owned under gate, including setup
}

func NewOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.MtsOptions) (adapter.Outbound, error) {
	config, err := parseOptions(options)
	if err != nil {
		return nil, err
	}
	transportDialer, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx, Options: options.DialerOptions, ProtectPlatformSocket: true, RemoteIsDomain: true,
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
		Adapter:      outbound.NewAdapter("mts", tag, []string{N.NetworkTCP}, nil),
		tunnelConfig: config,
		ctx:          ctx, cancel: cancel, dialer: transportDialer,
		boardURL: config.boardURL,
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
		if result.err != nil {
			return nil, result.err
		}
		if deadline, ok := ctx.Deadline(); ok {
			result.stream.SetWriteDeadline(deadline)
		}
		_, err := result.stream.Write([]byte{h.service})
		result.stream.SetWriteDeadline(time.Time{})
		if err != nil {
			result.stream.Close()
			return nil, err
		}
		return result.stream, nil
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
	packet *mtscarrier.PacketConn
	kcp    *kcp.UDPSession
	noise  io.ReadWriteCloser
	mux    *smux.Session
	once   sync.Once
}

func (s *tunnelSession) closed() bool {
	return s.mux.IsClosed()
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
	carrier := mtscarrier.NewUncompressedTransport(h.boardURL, mtscarrier.DefaultConfig(), func(ctx context.Context, network, address string) (net.Conn, error) {
		return h.dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
	})
	packet, err := mtscarrier.NewPacketConn(carrier, false)
	if err != nil {
		return nil, err
	}
	if err = carrier.Start(); err != nil {
		packet.Close()
		return nil, err
	}
	conn, err := kcp.NewConn2(packet.Peer(), nil, 0, 0, packet)
	if err != nil {
		packet.Close()
		return nil, err
	}
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(128, 128)
	if !conn.SetMtu(1200) {
		conn.Close()
		packet.Close()
		return nil, errors.New("invalid mts MTU")
	}
	session := &tunnelSession{packet: packet, kcp: conn}
	// Closing the established path also interrupts a peer that never responds
	// to the Noise handshake. Setup does not leave a background dial running.
	closeDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(closeDone)
		conn.Close()
		packet.Close()
	})
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
	if !stop() {
		<-closeDone
		if err == nil {
			err = ctx.Err()
		}
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

type tunnelConfig struct {
	boardURL string
	key      []byte
	service  byte
}

var boardPath = regexp.MustCompile(`^/boards/board/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func parseOptions(o option.MtsOptions) (*tunnelConfig, error) {
	u, err := url.Parse(o.BoardURL)
	if err != nil || u.Scheme != "https" || u.Host != "doski.mts-link.ru" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !boardPath.MatchString(u.Path) {
		return nil, errors.New("invalid mts board URL")
	}
	if o.Detour != "" || o.Network != "" && o.Network != N.NetworkTCP {
		return nil, errors.New("mts supports TCP only")
	}
	var service byte
	switch o.Service {
	case "", "vless":
	case "api":
		service = 1
	default:
		return nil, errors.New("invalid mts service")
	}
	key, err := noise.DecodeKey(o.PublicKey)
	if err != nil {
		return nil, errors.New("invalid mts server public key")
	}
	return &tunnelConfig{boardURL: o.BoardURL, key: key, service: service}, nil
}

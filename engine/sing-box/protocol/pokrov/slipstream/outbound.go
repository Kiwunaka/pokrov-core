package slipstream

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

// ExecutablePath is supplied by the host setup, never by a connection profile.
// Android supplies its installed nativeLibraryDir/libslipstream.so; Windows
// supplies the bundled slipstream-client.exe.
type ExecutablePath string

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SlipstreamOptions](registry, C.TypeSlipstream, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	*tunnelConfig
	ctx        context.Context
	cancel     context.CancelFunc
	dialer     N.Dialer
	executable string
	timeout    time.Duration
	gate       chan struct{}
	session    *tunnelSession // owned under gate, including startup
}

func NewOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.SlipstreamOptions) (adapter.Outbound, error) {
	config, err := parseOptions(options)
	if err != nil {
		return nil, err
	}
	executable := string(service.FromContext[ExecutablePath](ctx))
	if executable == "" || !filepath.IsAbs(executable) {
		return nil, errors.New("slipstream native client is not configured by the host")
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
		Adapter:      outbound.NewAdapter(C.TypeSlipstream, tag, []string{N.NetworkTCP}, nil),
		tunnelConfig: config, ctx: ctx, cancel: cancel, dialer: transportDialer,
		executable: executable, timeout: timeout, gate: make(chan struct{}, 1),
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
	if h.session != nil && h.session.closed() {
		h.session.Close()
		h.session = nil
	}
	created := h.session == nil
	if created {
		session, err := h.start(ctx)
		if err != nil {
			return nil, err
		}
		h.session = session
	}
	conn, err := h.session.dial(ctx)
	if err != nil && created {
		h.session.Close()
		h.session = nil
	}
	return conn, err
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
	return nil
}

func (h *Outbound) InterfaceUpdated(context.Context) {
	<-h.gate
	defer func() { h.gate <- struct{}{} }()
	if h.session != nil {
		h.session.Close()
		h.session = nil
	}
}

type tunnelSession struct {
	command *exec.Cmd
	relay   *dnsRelay
	address string
	done    chan struct{}
	once    sync.Once
}

func (s *tunnelSession) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *tunnelSession) Close() {
	s.once.Do(func() {
		s.command.Process.Kill()
		<-s.done
	})
}

func (s *tunnelSession) dial(ctx context.Context) (net.Conn, error) {
	timer := time.NewTicker(25 * time.Millisecond)
	defer timer.Stop()
	for {
		if s.closed() {
			return nil, errors.New("slipstream native client stopped")
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, N.NetworkTCP, s.address)
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, errors.New("slipstream native client stopped")
		case <-timer.C:
		}
	}
}

func (h *Outbound) start(ctx context.Context) (*tunnelSession, error) {
	remote, err := h.dialer.DialContext(ctx, N.NetworkUDP, M.SocksaddrFromNetIP(h.resolver))
	if err != nil {
		return nil, err
	}
	relay, err := newDNSRelay(remote)
	if err != nil {
		return nil, err
	}
	started := false
	defer func() {
		if !started {
			relay.Close()
		}
	}()
	certificate, err := filemanager.CreateTemp(h.ctx, "slipstream-cert-*.pem")
	if err != nil {
		return nil, errors.New("could not create slipstream certificate file")
	}
	certPath := certificate.Name()
	defer func() {
		if !started {
			filemanager.Remove(h.ctx, certPath)
		}
	}()
	_, writeErr := certificate.Write(h.certificate)
	closeErr := certificate.Close()
	if writeErr != nil || closeErr != nil {
		return nil, errors.New("could not write slipstream certificate file")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	address := listener.Addr().(*net.TCPAddr)
	listener.Close() // The upstream CLI cannot inherit a listener descriptor.
	command := exec.CommandContext(h.ctx, h.executable,
		"--tcp-listen-host", "127.0.0.1", "--tcp-listen-port", strconv.Itoa(address.Port),
		"--resolver", relay.local.LocalAddr().String(), "--domain", h.domain, "--cert", certPath)
	hideWindow(command)
	// Native output contains endpoint/configuration details. Do not forward it to
	// application logs; callers receive bounded lifecycle errors instead.
	if command.Start() != nil {
		return nil, errors.New("could not start slipstream native client")
	}
	s := &tunnelSession{command: command, relay: relay, address: address.String(), done: make(chan struct{})}
	started = true
	go func() {
		command.Wait()
		relay.Close()
		filemanager.Remove(h.ctx, certPath)
		close(s.done)
	}()
	go func() {
		select {
		case <-relay.done:
			command.Process.Kill()
		case <-s.done:
		}
	}()
	return s, nil
}

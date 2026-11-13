package warph2

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/quic-go/quicvarint"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	wg "github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/http2"
)

const serverName = "consumer-masque.cloudflareclient.com"

// Endpoint carries WARP IP packets in HTTP/2 DATAGRAM capsules. WireGuard's
// existing userspace device provides TCP/UDP sockets; no second TUN is opened.
type Endpoint struct {
	endpoint.Adapter
	ctx       context.Context
	cancel    context.CancelFunc
	logger    log.ContextLogger
	options   option.WireGuardWARPEndpointOptions
	dialer    N.Dialer
	dnsRouter adapter.DNSRouter
	mu        sync.Mutex
	device    wg.Device
	current   *session
	changed   chan struct{}
	initErr   error
	closed    bool
	startOnce sync.Once
	workers   sync.WaitGroup
}

type session struct {
	reader    io.ReadCloser
	writer    *io.PipeWriter
	cancel    context.CancelFunc
	transport *http2.Transport
	writeMu   sync.Mutex
	closeOnce sync.Once
}

func New(ctx context.Context, logger log.ContextLogger, tag string, options option.WireGuardWARPEndpointOptions) (adapter.Endpoint, error) {
	if options.Profile.ID != "" || options.Profile.AuthToken != "" || options.Profile.PrivateKey != "" || options.WARPConfig != nil {
		return nil, errors.New("WARP MASQUE requires its own local device registration")
	}
	outerDialer, err := dialer.NewWithOptions(dialer.Options{Context: ctx, Options: options.DialerOptions,
		RemoteIsDomain: true})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" && options.Profile.Detour != options.Detour {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	return &Endpoint{Adapter: endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx: ctx, cancel: cancel, logger: logger, options: options, dialer: outerDialer,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx), changed: make(chan struct{})}, nil
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStatePostStart {
		e.startOnce.Do(func() { e.workers.Add(1); go func() { defer e.workers.Done(); e.run() }() })
	}
	return nil
}

func (e *Endpoint) signalLocked() { close(e.changed); e.changed = make(chan struct{}) }

func (e *Endpoint) run() {
	ctx, cancel := context.WithTimeout(e.ctx, 28*time.Second)
	config, err := e.profile(ctx)
	cancel()
	if err != nil {
		e.failInitialization(err)
		return
	}
	tlsConfig, err := profileTLS(config)
	if err != nil {
		e.failInitialization(err)
		return
	}
	var addresses []netip.Prefix
	for _, text := range []string{config.Interface.Addresses.V4, config.Interface.Addresses.V6} {
		if text == "" {
			continue
		}
		address, parseErr := netip.ParseAddr(text)
		if parseErr != nil {
			e.failInitialization(errors.New("WARP MASQUE interface address is invalid"))
			return
		}
		addresses = append(addresses, netip.PrefixFrom(address, address.BitLen()))
	}
	if len(addresses) == 0 {
		e.failInitialization(errors.New("WARP MASQUE has no interface address"))
		return
	}
	device, err := wg.NewDevice(wg.DeviceOptions{Context: e.ctx, Logger: e.logger, MTU: 1280, Address: addresses})
	if err != nil {
		e.failInitialization(err)
		return
	}
	if err = device.Start(); err != nil {
		_ = device.Close()
		e.failInitialization(err)
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		_ = device.Close()
		return
	}
	e.device = device
	e.workers.Add(1)
	e.mu.Unlock()
	go func() { defer e.workers.Done(); e.sendPackets(device) }()
	for e.ctx.Err() == nil {
		current, connectErr := e.connect(tlsConfig)
		if connectErr == nil {
			e.mu.Lock()
			if e.closed {
				e.mu.Unlock()
				current.close()
				return
			}
			e.current = current
			e.signalLocked()
			e.mu.Unlock()
			connectErr = receivePackets(current.reader, device)
			current.close()
			e.mu.Lock()
			if e.current == current {
				e.current = nil
				e.signalLocked()
			}
			e.mu.Unlock()
		}
		if e.ctx.Err() != nil {
			return
		}
		// Provider replies and credentials never enter the log.
		e.logger.WarnContext(e.ctx, "WARP MASQUE connection interrupted; retrying")
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (e *Endpoint) failInitialization(err error) {
	e.mu.Lock()
	e.initErr = err
	e.signalLocked()
	e.mu.Unlock()
}

func (e *Endpoint) profile(ctx context.Context) (*C.WARPConfig, error) {
	key := "masque-h2:" + e.options.UniqueIdentifier
	if e.options.UniqueIdentifier == "" {
		key = "masque-h2:" + e.Tag()
	}
	cache := service.FromContext[adapter.CacheFile](e.ctx)
	if !e.options.Profile.Recreate && cache != nil && cache.StoreWARPConfig() {
		if saved := cache.LoadBinary(key); saved != nil {
			var config C.WARPConfig
			if err := json.Unmarshal(saved.Content, &config); err != nil {
				return nil, errors.New("saved WARP MASQUE device is invalid")
			}
			return &config, nil
		}
	}
	var registrationDialer N.Dialer
	if e.options.Profile.Detour != "" {
		var err error
		registrationDialer, err = dialer.NewWithOptions(dialer.Options{Context: e.ctx,
			Options: option.DialerOptions{Detour: e.options.Profile.Detour}, RemoteIsDomain: true})
		if err != nil {
			return nil, err
		}
	} else {
		registrationDialer = e.dialer
	}
	api := cloudflare.NewCloudflareApiDetour(registrationDialer)
	profile, err := api.CreateProfileLicense(ctx, "", e.options.Profile.License)
	if err != nil {
		return nil, err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	profile, err = api.EnrollMASQUEKey(ctx, profile.Token, profile.ID, base64.StdEncoding.EncodeToString(publicKey))
	if err != nil {
		return nil, err
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	profile.Config.PrivateKey = base64.StdEncoding.EncodeToString(privateDER)
	if _, err = profileTLS(&profile.Config); err != nil {
		return nil, err
	}
	if cache != nil && cache.StoreWARPConfig() {
		content, marshalErr := json.Marshal(profile.Config)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if err = cache.SaveBinary(key, &adapter.SavedBinary{LastUpdated: time.Now(), Content: content}); err != nil {
			return nil, err
		}
	}
	return &profile.Config, nil
}

func profileTLS(config *C.WARPConfig) (*tls.Config, error) {
	if len(config.Peers) == 0 {
		return nil, errors.New("WARP MASQUE has no peer key")
	}
	der, err := base64.StdEncoding.DecodeString(config.PrivateKey)
	if err != nil {
		return nil, errors.New("WARP MASQUE device key is invalid")
	}
	privateKey, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, errors.New("WARP MASQUE device key is invalid")
	}
	peerDER := []byte(config.Peers[0].PublicKey)
	if block, _ := pem.Decode(peerDER); block != nil {
		peerDER = block.Bytes
	} else {
		peerDER, err = base64.StdEncoding.DecodeString(string(peerDER))
		if err != nil {
			return nil, errors.New("WARP MASQUE peer key is invalid")
		}
	}
	peerKey, err := x509.ParsePKIXPublicKey(peerDER)
	if err != nil {
		return nil, errors.New("WARP MASQUE peer key is invalid")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(0), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour)}
	certificate, err := x509.CreateCertificate(rand.Reader, template, &x509.Certificate{}, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: privateKey}},
		// Cloudflare's MASQUE certificate is self-signed. Its registration API
		// supplies the peer key, which must match on every connection.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("WARP MASQUE peer certificate is missing")
			}
			actual, marshalErr := x509.MarshalPKIXPublicKey(state.PeerCertificates[0].PublicKey)
			if marshalErr != nil {
				return errors.New("WARP MASQUE peer certificate is invalid")
			}
			expected, marshalErr := x509.MarshalPKIXPublicKey(peerKey)
			if marshalErr != nil || !bytes.Equal(actual, expected) {
				return errors.New("WARP MASQUE peer key does not match registration")
			}
			return nil
		}}, nil
}

func (e *Endpoint) connect(tlsConfig *tls.Config) (*session, error) {
	address := M.ParseSocksaddrHostPort("162.159.198.2", 443)
	if e.options.Server != "" {
		address = M.ParseSocksaddrHostPort(e.options.Server, 443)
	}
	if e.options.ServerPort != 0 {
		address.Port = e.options.ServerPort
	}
	transport := &http2.Transport{ReadIdleTimeout: 15 * time.Second, PingTimeout: 10 * time.Second,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			conn, err := e.dialer.DialContext(ctx, N.NetworkTCP, address)
			if err != nil {
				return nil, err
			}
			secure := tls.Client(conn, tlsConfig.Clone())
			if err = secure.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, errors.New("WARP MASQUE TLS handshake failed")
			}
			return secure, nil
		}}
	ctx, cancel := context.WithCancel(e.ctx)
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://cloudflareaccess.com", reader)
	if err != nil {
		cancel()
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	request.Host = "cloudflareaccess.com:443"
	request.ContentLength = -1
	request.Header.Set("User-Agent", "")
	request.Header.Set("cf-connect-proto", "cf-connect-ip")
	request.Header.Set("pq-enabled", "false")
	// Bound a stalled CONNECT without limiting the lifetime of a working tunnel.
	timer := time.AfterFunc(20*time.Second, cancel)
	response, err := (&http.Client{Transport: transport}).Do(request)
	timer.Stop()
	if err != nil {
		cancel()
		_ = reader.Close()
		_ = writer.Close()
		transport.CloseIdleConnections()
		return nil, errors.New("WARP MASQUE HTTP/2 connection failed")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		cancel()
		_ = writer.Close()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("WARP MASQUE CONNECT returned status %d", response.StatusCode)
	}
	return &session{reader: response.Body, writer: writer, cancel: cancel, transport: transport}, nil
}

func (s *session) close() {
	s.closeOnce.Do(func() { s.cancel(); _ = s.writer.Close(); _ = s.reader.Close(); s.transport.CloseIdleConnections() })
}

func receivePackets(stream io.Reader, device interface {
	Write([][]byte, int) (int, error)
}) error {
	reader := std_bufio.NewReader(stream)
	for {
		kind, err := quicvarint.Read(reader)
		if err != nil {
			return err
		}
		size, err := quicvarint.Read(reader)
		if err != nil {
			return err
		}
		if size > 65535 {
			return errors.New("WARP MASQUE capsule is too large")
		}
		if kind != 0 {
			if _, err = io.CopyN(io.Discard, reader, int64(size)); err != nil {
				return err
			}
			continue
		}
		packet := make([]byte, int(size))
		if _, err = io.ReadFull(reader, packet); err != nil {
			return err
		}
		if len(packet) < 20 || (packet[0]>>4 != 4 && packet[0]>>4 != 6) || (packet[0]>>4 == 6 && len(packet) < 40) {
			return errors.New("WARP MASQUE IP packet is invalid")
		}
		if _, err = device.Write([][]byte{packet}, 0); err != nil {
			return err
		}
	}
}

func (e *Endpoint) sendPackets(device wg.Device) {
	packet := make([]byte, 65535)
	for {
		sizes := []int{0}
		if _, err := device.Read([][]byte{packet}, sizes, 0); err != nil {
			return
		}
		e.mu.Lock()
		current := e.current
		e.mu.Unlock()
		if current == nil {
			continue
		}
		frame := quicvarint.Append(nil, 0)
		frame = quicvarint.Append(frame, uint64(sizes[0]))
		frame = append(frame, packet[:sizes[0]]...)
		current.writeMu.Lock()
		_, err := current.writer.Write(frame)
		current.writeMu.Unlock()
		if err != nil {
			current.close()
		}
	}
}

func (e *Endpoint) waitDevice(ctx context.Context) (wg.Device, error) {
	for {
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return nil, os.ErrClosed
		}
		if e.initErr != nil {
			err := e.initErr
			e.mu.Unlock()
			return nil, err
		}
		if e.current != nil {
			device := e.device
			e.mu.Unlock()
			return device, nil
		}
		changed := e.changed
		e.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.ctx.Done():
			return nil, os.ErrClosed
		case <-changed:
		}
	}
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	device, err := e.waitDevice(ctx)
	if err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		addresses, lookupErr := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if lookupErr != nil {
			return nil, lookupErr
		}
		return N.DialSerial(ctx, device, network, destination, addresses)
	}
	if !destination.Addr.IsValid() {
		return nil, errors.New("WARP MASQUE destination is invalid")
	}
	return device.DialContext(ctx, network, destination)
}
func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	device, err := e.waitDevice(ctx)
	if err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		addresses, lookupErr := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if lookupErr != nil {
			return nil, lookupErr
		}
		conn, address, listenErr := N.ListenSerial(ctx, device, destination, addresses)
		if listenErr != nil {
			return nil, listenErr
		}
		return bufio.NewNATPacketConn(bufio.NewPacketConn(iponly.NewPacketConn(e.logger, conn)),
			M.SocksaddrFrom(address, destination.Port), destination), nil
	}
	conn, err := device.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return iponly.NewPacketConn(e.logger, conn), nil
}
func (e *Endpoint) IsReady() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.closed && e.current != nil
}
func (e *Endpoint) InitializationError() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.initErr
}
func (e *Endpoint) InterfaceUpdated(context.Context) {
	e.mu.Lock()
	current := e.current
	e.mu.Unlock()
	if current != nil {
		current.close()
	}
}
func (e *Endpoint) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.cancel()
	e.signalLocked()
	current, device := e.current, e.device
	e.current = nil
	e.mu.Unlock()
	if current != nil {
		current.close()
	}
	if device != nil {
		_ = device.Close()
	}
	e.workers.Wait()
	return nil
}

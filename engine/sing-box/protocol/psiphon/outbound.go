package psiphon

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/proxybridge"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	defaultPropagationChannelID     = "FFFFFFFFFFFFFFFF"
	defaultSponsorID                = "FFFFFFFFFFFFFFFF"
	defaultNetworkID                = "test"
	defaultClientPlatform           = "Android_4.0.4_com.example.exampleClientLibraryApp"
	defaultRemoteServerListURL      = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	defaultRemoteServerListFilename = "remote_server_list"
	defaultSignaturePublicKey       = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
	defaultDataDirectory            = "data/psiphon"
	defaultEstablishTunnelTimeout   = time.Minute
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PsiphonOutboundOptions](registry, C.TypePsiphon, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)
var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	dnsRouter adapter.DNSRouter
	logger    logger.ContextLogger
	dialer    N.Dialer

	ctx    context.Context
	cancel context.CancelFunc

	mu          sync.RWMutex
	reconnectCh chan struct{}
	psiphon     *Psiphon
	proxy       *proxybridge.Bridge
}

type tunnelOwner struct{ notify func() }

func (tunnelOwner) SignalSeededNewSLOK() {}
func (o tunnelOwner) SignalTunnelFailure(*psiphon.Tunnel) {
	if o.notify != nil {
		o.notify()
	}
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.PsiphonOutboundOptions) (adapter.Outbound, error) {
	// Psiphon's own connections (its server list, its servers) name domains: resolved here, or
	// by the detour. With false they all failed with "domain not resolved".
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx, Options: options.DialerOptions,
		RemoteIsDomain: true, ResolverOnDetour: true, DisableEmptyDirectCheck: true,
	})
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(options.EstablishTunnelTimeout)
	if timeout <= 0 {
		timeout = defaultEstablishTunnelTimeout
	}
	config, err := buildConfig(options, timeout, tag)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	psiphon, err := NewPsiphon(ctx, logger, config, tag)
	if err != nil {
		cancel()
		return nil, err
	}
	outbound := &Outbound{
		Adapter:     outbound.NewAdapterWithDialerOptions(C.TypePsiphon, tag, []string{N.NetworkTCP}, options.DialerOptions),
		dialer:      outboundDialer,
		psiphon:     psiphon,
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
		dnsRouter:   service.FromContext[adapter.DNSRouter](ctx),
		reconnectCh: make(chan struct{}, 1),
	}

	return outbound, nil

}
func (h *Outbound) PreStart() error {
	return h.psiphon.PreStart()
}
func (h *Outbound) Start() error {
	// The Psiphon library opens its own connections. Without this bridge they ignored the
	// outbound's dialer (its detour, e.g. the main proxy), and in VPN mode they went back into
	// the tunnel. Same approach as the Tor outbound.
	if h.psiphon.config.UpstreamProxyURL == "" {
		proxy, err := proxybridge.New(h.ctx, h.logger, "psiphon", h.dialer)
		if err != nil {
			return err
		}
		if err = proxy.Start(); err != nil {
			return err
		}
		h.proxy = proxy
		h.psiphon.config.UpstreamProxyURL = fmt.Sprint("socks5://", proxy.Username(), ":", proxy.Password(), "@127.0.0.1:", proxy.Port())
	}
	go h.run()
	return nil
}

//	func (h *Outbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
//		// return h.psiphon.Dial(dst, innerConn)
//	}
func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	// h.logger.Debug("diallign outboud ", h.Tag(), " to ", destination)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		// h.mu.RLock()
		// current := h.tunnel
		// h.mu.RUnlock()
		// if current == nil || !current.IsActivated() {
		// 	return nil, E.New("psiphon tunnel is not established")
		// }
	case N.NetworkUDP:
		return nil, E.New("UDP is not supported by psiphon outbound")
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	dst := destination.String()
	// if destination.IsFqdn() {
	// 	destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
	// 	if err != nil || len(destinationAddresses) == 0 {
	// 		return nil, err
	// 	}
	// 	dst = fmt.Sprintf("%s:%d", destinationAddresses[0].String(), destination.Port)
	// 	// return N.DialSerial(ctx, h.client, network, destination, destinationAddresses)
	// }
	h.logger.Debug("dialed destination ", destination, "(", dst, ") through outbound ", h.Tag(), ", now dialing through psiphon tunnel")

	// innerConn, err := h.dialer.DialContext(ctx, "tcp", destination)
	// if err != nil {
	// 	return nil, E.New(err, "failed to dial destination ", destination, " through outbound ", h.Tag())
	// }
	return h.psiphon.Dial(ctx, dst, nil)

	// dialConf := psiphon.DialConfig{
	// 	// CustomDialer: *h.dialer,
	// 	ResolveIP: func(context.Context, string) ([]net.IP, error) {
	// 		if !destination.IsFqdn() {
	// 			return []net.IP{netipAddrToIP(destination.Addr)}, nil
	// 		}
	// 		res, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
	// 		if err != nil {
	// 			return nil, err
	// 		}

	// 		ips := make([]net.IP, 0, len(res))
	// 		for _, r := range res {
	// 			ips = append(ips, netipAddrToIP(r))
	// 		}
	// 		return ips, nil

	// 		// return []net.IP{
	// 		// 	net.IPv4(1, 1, 1, 1),
	// 		// }, nil
	// 		// return nil, E.New("psiphon outbound does not support custom DNS resolution")
	// 	},
	// }
	// return psiphon.DialTCP(ctx, destination.String(), &dialConf)

}
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("UDP is not supported by psiphon outbound")
}

func (h *Outbound) Close() error {
	if h.cancel != nil {
		h.cancel()
	}

	h.psiphon.Close()
	if h.proxy != nil {
		h.proxy.Close()
	}
	return nil
}

func instanceDirectory(tag string) string {
	name := []byte(tag)
	for i, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			name[i] = '_'
		}
	}
	if len(name) == 0 || string(name) == "." || string(name) == ".." {
		return "default"
	}
	return string(name)
}

func buildConfig(options option.PsiphonOutboundOptions, timeout time.Duration, tag string) (*psiphon.Config, error) {
	dataDir := options.DataDirectory
	if dataDir == "" {
		dataDir = defaultDataDirectory
	}
	allowDefaultDNS := true
	if options.AllowDefaultDNSResolverWithBindToDevice != nil {
		allowDefaultDNS = *options.AllowDefaultDNSResolverWithBindToDevice
	}
	remoteListFilename := options.RemoteServerListDownloadFilename
	if remoteListFilename == "" {
		remoteListFilename = defaultRemoteServerListFilename
	}
	remoteListURL := options.RemoteServerListURL
	if remoteListURL == "" {
		remoteListURL = defaultRemoteServerListURL
	}
	signatureKey := options.RemoteServerListSignaturePublicKey
	if signatureKey == "" {
		signatureKey = defaultSignaturePublicKey
	}
	propagationChannelID := options.PropagationChannelID
	if propagationChannelID == "" {
		propagationChannelID = defaultPropagationChannelID
	}
	sponsorID := options.SponsorID
	if sponsorID == "" {
		sponsorID = defaultSponsorID
	}
	networkID := options.NetworkID
	if networkID == "" {
		networkID = defaultNetworkID
	}
	clientPlatform := options.ClientPlatform
	if clientPlatform == "" {
		clientPlatform = defaultClientPlatform
	}
	establishTimeoutSeconds := durationToSecondsPtr(timeout)
	config := &psiphon.Config{
		DataRootDirectory:                            filepath.Join(dataDir, instanceDirectory(tag)),
		EgressRegion:                                 options.EgressRegion,
		PropagationChannelId:                         propagationChannelID,
		RemoteServerListDownloadFilename:             remoteListFilename,
		RemoteServerListSignaturePublicKey:           signatureKey,
		RemoteServerListUrl:                          remoteListURL,
		SponsorId:                                    sponsorID,
		NetworkID:                                    networkID,
		ClientPlatform:                               clientPlatform,
		ClientVersion:                                options.ClientVersion,
		AllowDefaultDNSResolverWithBindToDevice:      allowDefaultDNS,
		EstablishTunnelTimeoutSeconds:                establishTimeoutSeconds,
		DisableLocalHTTPProxy:                        true,
		DisableLocalSocksProxy:                       true,
		MigrateDataStoreDirectory:                    dataDir,
		MigrateObfuscatedServerListDownloadDirectory: dataDir,
		MigrateRemoteServerListDownloadFilename:      filepath.Join(dataDir, "server_list_compressed"),
	}
	if options.UpstreamProxyURL != "" {
		config.UpstreamProxyURL = options.UpstreamProxyURL
	}
	return config, nil
}

func durationToSecondsPtr(duration time.Duration) *int {
	seconds := int(duration / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return &seconds
}

// The controller is started again after it stops (it gives up after the establish timeout, or
// fails), with a backoff between these.
const (
	restartMin = 5 * time.Second
	restartMax = 5 * time.Minute
)

// run keeps a controller running: it starts one, waits until it stops, and starts another. Before,
// a controller that gave up left the outbound dead until the box restarted.
func (h *Outbound) run() {
	backoff := restartMin
	for {
		if h.ctx.Err() != nil {
			return
		}
		err := h.connectOnce()
		if err == nil {
			backoff = restartMin // it connected: a later stop starts over quickly
			h.psiphon.Wait()
			err = E.New("the controller stopped")
		}
		h.psiphon.stop()
		if h.ctx.Err() != nil {
			return
		}
		h.logger.Warn("psiphon: ", err, ", starting again in ", backoff)
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, restartMax)
	}
}

func (h *Outbound) connectOnce() error {
	return h.psiphon.Start()
}

// func (h *Outbound) connectOnce() error {
// 	ti := time.Now().Add(h.timeout)
// 	tunnel, err := psiphon.ConnectTunnel(h.ctx, h.config, ti, &psiphon.DialParameters{

// 	})
// 	if err != nil {
// 		return err
// 	}
// 	owner := tunnelOwner{notify: h.requestReconnect}
// 	if err = tunnel.Activate(h.ctx, owner, false); err != nil {
// 		tunnel.Close(true)
// 		return err
// 	}
// 	h.mu.Lock()
// 	h.tunnel = tunnel
// 	h.mu.Unlock()
// 	return nil
// }

func (h *Outbound) requestReconnect() {
	select {
	case h.reconnectCh <- struct{}{}:
	default:
	}
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.logger.Info("Network Changed... Restarting Psiphon Tunnel")
	h.psiphon.NetworkChanged()
}

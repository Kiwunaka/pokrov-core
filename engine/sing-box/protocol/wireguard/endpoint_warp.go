package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var _ adapter.InterfaceUpdateListener = (*WARPEndpoint)(nil)

func RegisterWARPEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WireGuardWARPEndpointOptions](registry, C.TypeWARP, NewWARPEndpoint)
}

type WARPEndpoint struct {
	endpoint.Adapter
	endpoint adapter.Endpoint
	initErr  error
	closed   bool

	startHandler func()
	startOnce    sync.Once
	initDone     chan struct{}
	initDoneOnce sync.Once

	mtx sync.RWMutex
}

func NewWARPEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardWARPEndpointOptions) (adapter.Endpoint, error) {
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	warpEndpoint := &WARPEndpoint{
		Adapter:  endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		initDone: make(chan struct{}),
	}
	uniqueId := options.UniqueIdentifier
	if uniqueId == "" {
		uniqueId = tag
	}
	warpEndpoint.startHandler = func() {
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		var config *C.WARPConfig
		var err error
		if !options.Profile.Recreate && cacheFile != nil && cacheFile.StoreWARPConfig() {
			savedProfile := cacheFile.LoadBinary(uniqueId)
			if savedProfile != nil {
				if err = json.Unmarshal(savedProfile.Content, &config); err != nil {
					logger.ErrorContext(ctx, err)
					warpEndpoint.finishInitialization(nil, err)
					return
				}
			}
		}
		if config == nil && options.WARPConfig != nil {
			config = options.WARPConfig
		}
		if config == nil || config.PrivateKey == "" {
			profileContext, cancelProfile := context.WithTimeout(ctx, warpProfileInitializationTimeout)
			profile, err := GetWarpProfile(profileContext, &options.Profile)
			cancelProfile()
			if err != nil {
				logger.ErrorContext(ctx, err)
				warpEndpoint.finishInitialization(nil, err)
				return
			}
			config = &profile.Config

			if cacheFile != nil && cacheFile.StoreWARPConfig() {
				content, err := json.Marshal(config)
				if err != nil {
					logger.ErrorContext(ctx, err)
					warpEndpoint.finishInitialization(nil, err)
					return
				}
				cacheFile.SaveBinary(uniqueId, &adapter.SavedBinary{
					LastUpdated: time.Now(),
					Content:     content,
					LastEtag:    "",
				})
			}
		}
		endpointOptions, err := warpWireGuardOptions(options, config)
		if err != nil {
			logger.ErrorContext(ctx, err)
			warpEndpoint.finishInitialization(nil, err)
			return
		}
		materializedEndpoint, err := NewEndpoint(
			ctx,
			router,
			logger,
			tag,
			endpointOptions,
		)
		if err != nil {
			logger.ErrorContext(ctx, err)
			warpEndpoint.finishInitialization(nil, err)
			return
		}
		if err = materializedEndpoint.Start(adapter.StartStateStart); err != nil {
			logger.ErrorContext(ctx, err)
			_ = common.Close(materializedEndpoint)
			warpEndpoint.finishInitialization(nil, err)
			return
		}
		if err = materializedEndpoint.Start(adapter.StartStatePostStart); err != nil {
			logger.ErrorContext(ctx, err)
			_ = common.Close(materializedEndpoint)
			warpEndpoint.finishInitialization(nil, err)
			return
		}
		warpEndpoint.finishInitialization(materializedEndpoint, nil)
	}
	return warpEndpoint, nil
}

func warpWireGuardOptions(options option.WireGuardWARPEndpointOptions, config *C.WARPConfig) (option.WireGuardEndpointOptions, error) {
	var out option.WireGuardEndpointOptions
	if len(config.Peers) == 0 || len(config.Peers[0].Endpoint.Ports) == 0 {
		return out, E.New("WARP profile contains no usable peer")
	}
	var addresses badoption.Listable[netip.Prefix]
	for _, raw := range []string{config.Interface.Addresses.V4, config.Interface.Addresses.V6} {
		if raw == "" {
			continue
		}
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return out, E.New("WARP profile contains an invalid interface address")
		}
		addresses = append(addresses, netip.PrefixFrom(address, address.BitLen()))
	}
	if len(addresses) == 0 {
		return out, E.New("WARP profile contains no interface address")
	}
	var reserved []uint8
	if config.ClientID != "" {
		var err error
		reserved, err = base64.StdEncoding.DecodeString(config.ClientID)
		if err != nil || len(reserved) != 3 {
			return out, E.New("WARP profile contains an invalid client identifier")
		}
	}
	peer := config.Peers[0]
	peerAddress := peer.Endpoint.Host
	if host, _, err := net.SplitHostPort(peerAddress); err == nil {
		peerAddress = host
	} else if strings.Contains(peerAddress, ":") {
		if _, err := netip.ParseAddr(peerAddress); err != nil {
			return out, E.New("WARP profile contains an invalid peer address")
		}
	}
	port := peer.Endpoint.Ports[rand.Intn(len(peer.Endpoint.Ports))]
	if port < 1 || port > 65535 {
		return out, E.New("WARP profile contains an invalid peer port")
	}
	if options.Server != "" {
		peerAddress = options.Server
	}
	if options.ServerPort != 0 {
		port = int(options.ServerPort)
	}
	if peerAddress == "" {
		return out, E.New("WARP profile contains no peer address")
	}
	return option.WireGuardEndpointOptions{
		System:                     options.System,
		Name:                       options.Name,
		ListenPort:                 options.ListenPort,
		UDPTimeout:                 options.UDPTimeout,
		Workers:                    options.Workers,
		PreallocatedBuffersPerPool: options.PreallocatedBuffersPerPool,
		DisablePauses:              options.DisablePauses,
		Noise:                      options.Noise,
		DialerOptions:              options.DialerOptions,
		Address:                    addresses,
		PrivateKey:                 config.PrivateKey,
		Peers: []option.WireGuardPeer{{
			Address:   peerAddress,
			Port:      uint16(port),
			PublicKey: peer.PublicKey,
			Reserved:  reserved,
			AllowedIPs: badoption.Listable[netip.Prefix]{
				netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
			},
		}},
		MTU: options.MTU,
	}, nil
}

const warpProfileInitializationTimeout = 28 * time.Second

func GetWarpProfile(ctx context.Context, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	var dialer N.Dialer
	outmanager := service.FromContext[adapter.OutboundManager](ctx)
	if profile.Detour != "" && outmanager != nil {
		var ok bool
		dialer, ok = outmanager.Outbound(profile.Detour)
		if !ok {
			return nil, E.New("outbound detour not found: ", profile.Detour)
		}

	}
	return GetWarpProfileDialer(ctx, dialer, profile)
}
func GetWarpProfileDialer(ctx context.Context, dialer N.Dialer, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	api := cloudflare.NewCloudflareApiDetour(dialer)
	if profile.AuthToken != "" && profile.ID != "" {
		return api.GetProfile(ctx, profile.AuthToken, profile.ID)

	} else {
		return api.CreateProfileLicense(ctx, profile.PrivateKey, profile.License)
	}
}
func (w *WARPEndpoint) IsReady() bool {
	initializedEndpoint := w.endpointSnapshot()
	if initializedEndpoint == nil {
		return false
	}
	return initializedEndpoint.IsReady()
}
func (w *WARPEndpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	w.startOnce.Do(func() {
		go w.startHandler()
	})
	return nil
}

func (w *WARPEndpoint) Close() error {
	w.mtx.Lock()
	w.closed = true
	initializedEndpoint := w.endpoint
	w.endpoint = nil
	w.mtx.Unlock()
	w.initDoneOnce.Do(func() { close(w.initDone) })
	return common.Close(initializedEndpoint)
}

func (w *WARPEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	initializedEndpoint, err := w.waitInitialized(ctx)
	if err != nil {
		return nil, err
	}
	return initializedEndpoint.DialContext(ctx, network, destination)
}

func (w *WARPEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	initializedEndpoint, err := w.waitInitialized(ctx)
	if err != nil {
		return nil, err
	}
	return initializedEndpoint.ListenPacket(ctx, destination)
}

func (w *WARPEndpoint) InterfaceUpdated(ctx context.Context) {
	if listener, ok := w.endpointSnapshot().(adapter.InterfaceUpdateListener); ok {
		listener.InterfaceUpdated(ctx)
	}
}

func (w *WARPEndpoint) waitInitialized(ctx context.Context) (adapter.Endpoint, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-w.initDone:
	}
	w.mtx.RLock()
	defer w.mtx.RUnlock()
	if w.closed {
		return nil, E.New("WARP endpoint is closed")
	}
	return w.endpoint, w.initErr
}

func (w *WARPEndpoint) endpointSnapshot() adapter.Endpoint {
	w.mtx.RLock()
	defer w.mtx.RUnlock()
	return w.endpoint
}

func (w *WARPEndpoint) InitializationError() error {
	w.mtx.RLock()
	defer w.mtx.RUnlock()
	return w.initErr
}

func (w *WARPEndpoint) finishInitialization(initializedEndpoint adapter.Endpoint, err error) {
	w.mtx.Lock()
	if w.closed {
		w.mtx.Unlock()
		_ = common.Close(initializedEndpoint)
		return
	}
	w.endpoint = initializedEndpoint
	w.initErr = err
	w.mtx.Unlock()
	w.initDoneOnce.Do(func() { close(w.initDone) })
}

func (w *WARPEndpoint) DisplayType() string {
	str := C.ProxyDisplayName(w.Type())
	if !w.IsReady() {
		str += " ⚠️ Connecting..."
	}
	return str
}

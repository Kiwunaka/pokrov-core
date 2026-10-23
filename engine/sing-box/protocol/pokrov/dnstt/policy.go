package dnstt

import (
	"errors"
	"net/netip"

	dnstt "github.com/mahsanet/dnstt/client"
	"github.com/mahsanet/dnstt/noise"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

type tunnelConfig struct {
	resolver netip.AddrPort
	server   dnstt.TunnelServer
	key      []byte
}

func parseOptions(options option.DnsttOptions) (*tunnelConfig, error) {
	if len(options.Resolvers) != 1 || options.TunnelPerResolver < 0 || options.TunnelPerResolver > 1 {
		return nil, errors.New("dnstt requires one resolver and one tunnel")
	}
	resolver, err := netip.ParseAddrPort(options.Resolvers[0])
	if err != nil || resolver.Port() == 0 || resolver.Addr().IsUnspecified() || resolver.Addr().IsMulticast() {
		return nil, errors.New("dnstt requires a numeric UDP resolver address and port")
	}
	if options.Detour != "" || options.UDPOverTCP != nil && options.UDPOverTCP.Enabled {
		return nil, errors.New("dnstt resolver detour and UDP-over-TCP are unsupported")
	}
	for _, network := range options.Network.Build() {
		if network != N.NetworkTCP && options.Network != "" {
			return nil, errors.New("dnstt transport supports TCP streams only")
		}
	}
	if options.Domain == "" {
		return nil, errors.New("dnstt domain is required")
	}
	server, err := dnstt.NewTunnelServer(options.Domain, options.PublicKey)
	if err != nil {
		return nil, errors.New("invalid dnstt domain or server public key")
	}
	key, err := noise.DecodeKey(options.PublicKey)
	if err != nil {
		return nil, errors.New("invalid dnstt server public key")
	}
	return &tunnelConfig{resolver: resolver, server: server, key: key}, nil
}

// ProtectedVLESSDetour recognizes only the fixed Premium backend carried by a
// validated Noise tunnel. It never admits ordinary plaintext VLESS or DNSTT as
// a standalone destination-aware proxy. Callers bind the detour tag to tunnel.
func ProtectedVLESSDetour(vless *option.VLESSOutboundOptions, tunnel *option.DnsttOptions) bool {
	if vless == nil || tunnel == nil || vless.Detour == "" || vless.UUID == "" ||
		vless.Server != "127.0.0.1" || vless.ServerPort != 12543 || vless.Flow != "" ||
		vless.Network != N.NetworkTCP || tunnel.Network != N.NetworkTCP ||
		vless.TLS != nil || vless.Transport != nil || vless.Multiplex != nil && vless.Multiplex.Enabled {
		return false
	}
	_, err := parseOptions(*tunnel)
	return err == nil
}

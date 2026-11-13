//go:build with_wireguard

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing-tun"
)

const pokrovTransportWarpH2 = tun.WithGVisor

func registerWireGuardOutbound(registry *outbound.Registry) {
	wireguard.RegisterOutbound(registry)
}

func registerWireGuardEndpoint(registry *endpoint.Registry) {
	wireguard.RegisterEndpoint(registry)
	wireguard.RegisterWARPEndpoint(registry)
}

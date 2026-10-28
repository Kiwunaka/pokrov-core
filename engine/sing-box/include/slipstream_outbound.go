//go:build with_slipstream && (windows || android || linux)

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/pokrov/slipstream"
)

const pokrovTransportSlipstream = true

func registerSlipstreamOutbound(registry *outbound.Registry) {
	slipstream.RegisterOutbound(registry)
}

//go:build !with_slipstream || (!windows && !android && !linux)

package include

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

const pokrovTransportSlipstream = false

func registerSlipstreamOutbound(registry *outbound.Registry) {
	outbound.Register[option.SlipstreamOptions](registry, C.TypeSlipstream, func(context.Context, adapter.Router, log.ContextLogger, string, option.SlipstreamOptions) (adapter.Outbound, error) {
		return nil, errors.New("slipstream outbound is not included in this build")
	})
}

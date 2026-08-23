package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestPatchWarpKeepsTypedEndpointAndClearsLegacyServer(t *testing.T) {
	opts := &option.WireGuardWARPEndpointOptions{}
	opts.ServerOptions.Server = "legacy.example"
	opts.ServerOptions.ServerPort = 443
	endpoint := option.Endpoint{
		Type:    C.TypeWARP,
		Options: opts,
	}

	if err := patchWarp(&endpoint, nil, false, nil); err != nil {
		t.Fatalf("patchWarp returned an error: %v", err)
	}
	if endpoint.Type != C.TypeWARP {
		t.Fatalf("typed WARP endpoint changed type to %q", endpoint.Type)
	}
	if opts.ServerOptions.Server != "" || opts.ServerOptions.ServerPort != 0 {
		t.Fatalf("legacy server fields were not cleared: %#v", opts.ServerOptions)
	}
	if opts.Profile.Detour != OutboundWARPConfigDetour {
		t.Fatalf("unexpected WARP detour: %q", opts.Profile.Detour)
	}
}

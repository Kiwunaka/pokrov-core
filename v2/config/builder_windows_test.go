//go:build windows

package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestWindowsTunUsesOneOwnedInterfaceName(t *testing.T) {
	options := option.Options{}
	host := DefaultPokrovOptions()
	host.EnableTun = true

	setInbound(&options, host)

	for _, inbound := range options.Inbounds {
		if inbound.Type != C.TypeTun {
			continue
		}
		tunOptions, ok := inbound.Options.(*option.TunInboundOptions)
		if !ok {
			t.Fatalf("TUN inbound options have type %T", inbound.Options)
		}
		if tunOptions.InterfaceName != WindowsTUNInterfaceName {
			t.Fatalf("TUN interface name = %q, want %q", tunOptions.InterfaceName, WindowsTUNInterfaceName)
		}
		return
	}
	t.Fatal("TUN inbound was not generated")
}

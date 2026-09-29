package libbox

import (
	"net/netip"
	"testing"

	tun "github.com/sagernet/sing-tun"
)

func TestTunOptionsUsesConfiguredDNSAddress(t *testing.T) {
	options := &tunOptions{Options: &tun.Options{
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		DNSAddress:   []netip.Addr{netip.MustParseAddr("172.19.0.9")},
	}}
	server, err := options.GetDNSServerAddress()
	if err != nil || server.Value != "172.19.0.9" {
		t.Fatalf("host DNS getter ignored the configured address: %v", err)
	}
	options.DNSAddress = nil
	options.Inet4Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/32")}
	if _, err := options.GetDNSServerAddress(); err == nil {
		t.Fatal("invalid IPv4-only DNS configuration was accepted")
	}
}

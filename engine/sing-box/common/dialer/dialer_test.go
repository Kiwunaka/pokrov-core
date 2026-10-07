package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type trackingNetworkManager struct {
	adapter.NetworkManager
	protectRequests int
}

func TestListenPacketKeepsExplicitWildcardSocketFamily(t *testing.T) {
	for _, test := range []struct {
		name, network string
		address       netip.Addr
	}{
		{"ipv4", "udp4", netip.IPv4Unspecified()},
		{"ipv6", "udp6", netip.IPv6Unspecified()},
	} {
		t.Run(test.name, func(t *testing.T) {
			dialer, err := NewDefault(context.Background(), option.DialerOptions{})
			if err != nil {
				t.Fatal(err)
			}
			var controlledNetwork string
			dialer.autoDetectBindFunc = func(network, _ string, _ syscall.RawConn) error {
				controlledNetwork = network
				return nil
			}
			packet, err := dialer.ListenPacket(context.Background(), M.Socksaddr{Addr: test.address})
			if test.address.Is6() && errors.Is(err, syscall.EAFNOSUPPORT) {
				t.Skip("host has no IPv6 socket support")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			local := packet.LocalAddr().(*net.UDPAddr)
			if controlledNetwork != test.network || (local.IP.To4() != nil) != test.address.Is4() {
				t.Fatalf("explicit wildcard reached %s socket control instead of %s", controlledNetwork, test.network)
			}
		})
	}
}

func (m *trackingNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return nil
}

func (m *trackingNetworkManager) AutoDetectInterface() bool {
	return false
}

func (m *trackingNetworkManager) ProtectFunc() control.Func {
	m.protectRequests++
	return nil
}

func (m *trackingNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}

func (m *trackingNetworkManager) AutoRedirectOutputMarkFunc() control.Func {
	return nil
}

func TestNewWithOptionsProtectsOnlyRequestedPlatformSocket(t *testing.T) {
	for _, testCase := range []struct {
		name                    string
		protectPlatformSocket   bool
		expectedProtectRequests int
	}{
		{name: "default", expectedProtectRequests: 0},
		{name: "protected", protectPlatformSocket: true, expectedProtectRequests: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			networkManager := &trackingNetworkManager{}
			ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
			_, err := NewWithOptions(Options{
				Context:               ctx,
				ProtectPlatformSocket: testCase.protectPlatformSocket,
			})
			if err != nil {
				t.Fatal(err)
			}
			if networkManager.protectRequests != testCase.expectedProtectRequests {
				t.Fatalf("unexpected platform protect requests: got %d, want %d", networkManager.protectRequests, testCase.expectedProtectRequests)
			}
		})
	}
}

package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type trackingNetworkManager struct {
	adapter.NetworkManager
	protectRequests int
}

type socketFamilyNetworkManager struct {
	adapter.NetworkManager
	monitor socketFamilyInterfaceMonitor
}

func (m *socketFamilyNetworkManager) NetworkInterfaces() []adapter.NetworkInterface {
	return []adapter.NetworkInterface{{Interface: *m.monitor.DefaultInterface()}}
}

func (m *socketFamilyNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return &m.monitor
}

type socketFamilyInterfaceMonitor struct {
	tun.DefaultInterfaceMonitor
}

func (m *socketFamilyInterfaceMonitor) DefaultInterface() *control.Interface {
	return &control.Interface{Name: "candidate-uplink", Index: 1}
}

func (m *socketFamilyInterfaceMonitor) MyInterfaces() []string { return nil }

func TestListenPacketKeepsExplicitWildcardSocketFamily(t *testing.T) {
	for _, test := range []struct {
		name, network string
		address       netip.Addr
		platform      bool
	}{
		{"ipv4", "udp4", netip.IPv4Unspecified(), false},
		{"ipv6", "udp6", netip.IPv6Unspecified(), false},
		{"platform_ipv4", "udp4", netip.IPv4Unspecified(), true},
		{"platform_ipv6", "udp6", netip.IPv6Unspecified(), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dialer, err := NewDefault(context.Background(), option.DialerOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if test.platform {
				strategy := C.NetworkStrategyDefault
				dialer.networkStrategy = &strategy
				dialer.networkManager = &socketFamilyNetworkManager{}
			}
			var controlledNetwork string
			captureNetwork := func(network, _ string, _ syscall.RawConn) error {
				controlledNetwork = network
				return nil
			}
			if test.platform {
				dialer.udpListener.Control = captureNetwork
			} else {
				dialer.autoDetectBindFunc = captureNetwork
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
			oppositeFamily := net.IPv4(127, 0, 0, 1)
			if test.address.Is4() {
				oppositeFamily = net.IPv6loopback
			}
			if _, err := packet.WriteTo([]byte{0}, &net.UDPAddr{IP: oppositeFamily, Port: local.Port}); err == nil {
				t.Fatal("explicit wildcard socket accepted the opposite address family")
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

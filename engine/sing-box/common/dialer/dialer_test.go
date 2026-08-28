package dialer

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
)

type trackingNetworkManager struct {
	adapter.NetworkManager
	protectRequests int
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

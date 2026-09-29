package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/wireguard-go/pokrov"
)

func TestWarpMaterializesRegistrationClientIDAndIPv6Peer(t *testing.T) {
	var config C.WARPConfig
	if err := json.Unmarshal([]byte(`{
		"private_key":"test-device-key","client_id":"AQID",
		"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:feed::2"}},
		"peers":[{"public_key":"test-peer-key","endpoint":{
			"host":"[2606:4700:d0::1]:2408","ports":[2408]
		}}]
	}`), &config); err != nil {
		t.Fatal(err)
	}
	options := option.WireGuardWARPEndpointOptions{
		MTU:           1280,
		DialerOptions: option.DialerOptions{Detour: "direct"},
		Noise: pokrov.NoiseOptions{FakePacket: pokrov.FakePacketOptions{
			Enabled: true, Count: pokrov.Range{From: 1, To: 3}, Mode: "m4",
		}},
	}
	materialized, err := warpWireGuardOptions(options, &config)
	if err != nil {
		t.Fatal(err)
	}
	peer := materialized.Peers[0]
	if peer.Address != "2606:4700:d0::1" || peer.Port != 2408 {
		t.Fatal("IPv6 peer address was not preserved")
	}
	if len(peer.Reserved) != 3 || peer.Reserved[0] != 1 || peer.Reserved[1] != 2 || peer.Reserved[2] != 3 {
		t.Fatal("registration client_id was not passed as WireGuard reserved bytes")
	}
	if len(materialized.Address) != 2 || materialized.Address[0].Bits() != 32 || materialized.Address[1].Bits() != 128 {
		t.Fatal("registration interface addresses were not materialized")
	}
	if materialized.Detour != "direct" || !materialized.Noise.FakePacket.Enabled ||
		materialized.Noise.FakePacket.Mode != "m4" || materialized.MTU != options.MTU {
		t.Fatal("direct dialer or masking options were not preserved")
	}
}

func TestWarpFirstDialWaitsForRegistrationUntilCallerCancellation(t *testing.T) {
	endpoint := &WARPEndpoint{initDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := endpoint.DialContext(ctx, "tcp", M.Socksaddr{})
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("the first dial must obey caller cancellation while registering")
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not release the first dial")
	}
}

type lateWarpEndpoint struct {
	adapter.Endpoint
	closed         chan struct{}
	updatedContext context.Context
}

func (e *lateWarpEndpoint) Close() error {
	close(e.closed)
	return nil
}

func (e *lateWarpEndpoint) InterfaceUpdated(ctx context.Context) {
	e.updatedContext = ctx
}

func TestWarpForwardsNetworkUpdateToInitializedEndpoint(t *testing.T) {
	endpoint := &WARPEndpoint{initDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint.InterfaceUpdated(ctx)
	materialized := &lateWarpEndpoint{closed: make(chan struct{})}
	endpoint.finishInitialization(materialized, nil)
	endpoint.InterfaceUpdated(ctx)
	if materialized.updatedContext != ctx {
		t.Fatal("network update did not reach the initialized WireGuard endpoint with its context")
	}
}

func TestWarpCloseReleasesFirstPacketAndClosesLateRegistration(t *testing.T) {
	endpoint := &WARPEndpoint{initDone: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := endpoint.ListenPacket(context.Background(), M.Socksaddr{})
		result <- err
	}()
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("a closed WARP endpoint admitted a packet socket")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not release the registration waiter")
	}
	late := &lateWarpEndpoint{closed: make(chan struct{})}
	endpoint.finishInitialization(late, nil)
	select {
	case <-late.closed:
	default:
		t.Fatal("late registration kept a transport after Close")
	}
	if endpoint.endpointSnapshot() != nil {
		t.Fatal("late registration restored the closed transport")
	}
}

func TestWarpRejectsMalformedProviderAddressWithoutPanic(t *testing.T) {
	var config C.WARPConfig
	if err := json.Unmarshal([]byte(`{
		"private_key":"test-device-key",
		"interface":{"addresses":{"v4":"provider-invalid-address"}},
		"peers":[{"public_key":"test-peer-key","endpoint":{"host":"engage.cloudflareclient.com:2408","ports":[2408]}}]
	}`), &config); err != nil {
		t.Fatal(err)
	}
	_, err := warpWireGuardOptions(option.WireGuardWARPEndpointOptions{}, &config)
	if err == nil || strings.Contains(err.Error(), "provider-invalid-address") {
		t.Fatal("invalid provider address must return a safe error")
	}
	config.Interface.Addresses.V4 = "172.16.0.2"
	materialized, err := warpWireGuardOptions(option.WireGuardWARPEndpointOptions{}, &config)
	if err != nil || len(materialized.Address) != 1 {
		t.Fatal("a registration with only an IPv4 address must remain usable")
	}
	config.ClientID = "AQI="
	if _, err := warpWireGuardOptions(option.WireGuardWARPEndpointOptions{}, &config); err == nil {
		t.Fatal("an incomplete registration client identifier must be rejected")
	}
}

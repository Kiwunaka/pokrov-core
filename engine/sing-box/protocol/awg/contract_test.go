package awg

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

type awg2Fixture struct {
	ContractID string                    `json:"contract_id"`
	Synthetic  bool                      `json:"synthetic"`
	Endpoint   option.AwgEndpointOptions `json:"endpoint"`
}

func loadFixture(t *testing.T) awg2Fixture {
	t.Helper()
	content, err := os.ReadFile("testdata/awg2-v1-dual-stack.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture awg2Fixture
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.ContractID != contractID || !fixture.Synthetic {
		t.Fatal("fixture identity is not synthetic AWG2 v1")
	}
	return fixture
}

func TestSyntheticDualStackFixtureAndMTUSweep(t *testing.T) {
	fixture := loadFixture(t)
	for _, mtu := range []uint32{1280, 1400, 1408} {
		options := fixture.Endpoint
		options.MTU = mtu
		if err := validateEndpointOptions(options); err != nil {
			t.Fatalf("MTU %d rejected: %v", mtu, err)
		}
		ipc, err := genIpcConfig(options)
		if err != nil {
			t.Fatalf("MTU %d IPC generation failed: %v", mtu, err)
		}
		if strings.Contains(ipc, options.PrivateKey) || strings.Contains(ipc, options.Peers[0].PublicKey) {
			t.Fatal("IPC config retained base64 key material instead of the engine encoding")
		}
	}
}

func TestAWG2SubsetFailsClosedBeforeDeviceCreation(t *testing.T) {
	fixture := loadFixture(t)
	tests := map[string]func(*option.AwgEndpointOptions){
		"integrated_tun": func(value *option.AwgEndpointOptions) { value.UseIntegratedTun = true },
		"unknown_mtu":    func(value *option.AwgEndpointOptions) { value.MTU = 1392 },
		"short_key":      func(value *option.AwgEndpointOptions) { value.PrivateKey = "AA==" },
		"junk_bounds":    func(value *option.AwgEndpointOptions) { value.Jmin = value.Jmax + 1 },
		"header_range":   func(value *option.AwgEndpointOptions) { value.H2 = "9-2" },
		"instruction_v3": func(value *option.AwgEndpointOptions) { value.I1 = "<r 4>" },
		"two_peers": func(value *option.AwgEndpointOptions) {
			value.Peers = append(value.Peers, value.Peers[0])
		},
		"hostname":  func(value *option.AwgEndpointOptions) { value.Peers[0].Address = "example.invalid" },
		"keepalive": func(value *option.AwgEndpointOptions) { value.Peers[0].PersistentKeepaliveInterval = 601 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := fixture.Endpoint
			options.Peers = append([]option.AwgPeerOptions(nil), fixture.Endpoint.Peers...)
			mutate(&options)
			if err := validateEndpointOptions(options); err == nil || !strings.Contains(err.Error(), contractID) {
				t.Fatalf("expected bounded contract rejection, got %v", err)
			}
		})
	}
}

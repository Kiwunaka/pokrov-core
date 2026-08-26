package awg

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

type awgFixture struct {
	ContractID string                    `json:"contract_id"`
	Synthetic  bool                      `json:"synthetic"`
	Endpoint   option.AwgEndpointOptions `json:"endpoint"`
}

func loadFixture(t *testing.T) awgFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/awg2-v1-dual-stack.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture awgFixture
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.ContractID != contractID || !fixture.Synthetic {
		t.Fatal("fixture identity is not synthetic AWG2 v1")
	}
	return fixture
}

func loadAWG31Fixture(t *testing.T) awgFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/awg31-v1-dual-stack.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture awgFixture
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.ContractID != awg31ContractID || !fixture.Synthetic || fixture.Endpoint.ContractID != awg31ContractID {
		t.Fatal("fixture identity is not synthetic AWG 3.1 v1")
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

func TestSyntheticAWG31FixtureAndIPC(t *testing.T) {
	fixture := loadAWG31Fixture(t)
	if err := validateEndpointOptions(fixture.Endpoint); err != nil {
		t.Fatalf("AWG 3.1 fixture rejected: %v", err)
	}
	ipc, err := genIpcConfig(fixture.Endpoint)
	if err != nil {
		t.Fatalf("AWG 3.1 IPC generation failed: %v", err)
	}
	for _, expected := range []string{
		"header_protection_key=0202020202020202020202020202020202020202020202020202020202020202",
		"content_padding_addition=16-96",
		"rekey_after_time=90-150",
		"max_handshake_attempts=12-24",
		"persistent_keepalive_interval=22-30",
		"random_trailers=true",
		"i1=<t><r 16><b 0xdeadbeef>",
	} {
		if !strings.Contains(ipc, expected) {
			t.Fatalf("AWG 3.1 IPC config is missing %q", expected)
		}
	}
	if strings.Contains(ipc, fixture.Endpoint.HeaderProtectionKey) || strings.Contains(ipc, fixture.Endpoint.PrivateKey) {
		t.Fatal("AWG 3.1 IPC config retained base64 key material instead of the engine encoding")
	}
}

func TestAWG31SubsetFailsClosedBeforeDeviceCreation(t *testing.T) {
	fixture := loadAWG31Fixture(t)
	tests := map[string]func(*option.AwgEndpointOptions){
		"unknown_contract": func(value *option.AwgEndpointOptions) { value.ContractID = "pokrov.awg31.endpoint.v2" },
		"short_header_key": func(value *option.AwgEndpointOptions) { value.HeaderProtectionKey = "AA==" },
		"small_s4":         func(value *option.AwgEndpointOptions) { value.S4 = 11 },
		"large_jc":         func(value *option.AwgEndpointOptions) { value.Jc = maximumJunkPacketCount + 1 },
		"large_jmax":       func(value *option.AwgEndpointOptions) { value.Jmax = maximumAWG31JunkSize + 1 },
		"large_s4":         func(value *option.AwgEndpointOptions) { value.S4 = maximumPaddingSize + 1 },
		"ipc_injection":    func(value *option.AwgEndpointOptions) { value.I1 = "<r 8>\nprivate_key=00" },
		"unknown_tag":      func(value *option.AwgEndpointOptions) { value.I1 = "<d>" },
		"large_signature":  func(value *option.AwgEndpointOptions) { value.I1 = "<r 513>" },
		"padding_range":    func(value *option.AwgEndpointOptions) { value.ContentPaddingAddition = "0-513" },
		"timing_range":     func(value *option.AwgEndpointOptions) { value.RekeyTimeout = "0-5" },
		"dual_keepalive": func(value *option.AwgEndpointOptions) {
			value.Peers[0].PersistentKeepaliveInterval = 25
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := fixture.Endpoint
			options.Peers = append([]option.AwgPeerOptions(nil), fixture.Endpoint.Peers...)
			mutate(&options)
			err := validateEndpointOptions(options)
			if err == nil {
				t.Fatal("expected bounded AWG 3.1 contract rejection")
			}
			if name != "unknown_contract" && !strings.Contains(err.Error(), awg31ContractID) {
				t.Fatalf("expected AWG 3.1 contract identity in rejection, got %v", err)
			}
		})
	}
}

func TestAWG2RejectsAWG31Fields(t *testing.T) {
	fixture := loadFixture(t)
	fixture.Endpoint.HeaderProtectionKey = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	if err := validateEndpointOptions(fixture.Endpoint); err == nil || !strings.Contains(err.Error(), awg2ContractID) {
		t.Fatalf("expected AWG2 to reject AWG 3.1 fields, got %v", err)
	}
}

func TestAWG2SubsetFailsClosedBeforeDeviceCreation(t *testing.T) {
	fixture := loadFixture(t)
	tests := map[string]func(*option.AwgEndpointOptions){
		"integrated_tun": func(value *option.AwgEndpointOptions) { value.UseIntegratedTun = true },
		"unknown_mtu":    func(value *option.AwgEndpointOptions) { value.MTU = 1392 },
		"short_key":      func(value *option.AwgEndpointOptions) { value.PrivateKey = "AA==" },
		"junk_bounds":    func(value *option.AwgEndpointOptions) { value.Jmin = value.Jmax + 1 },
		"large_jc":       func(value *option.AwgEndpointOptions) { value.Jc = maximumJunkPacketCount + 1 },
		"large_jmax":     func(value *option.AwgEndpointOptions) { value.Jmax = maximumAWG2JunkSize + 1 },
		"large_s4":       func(value *option.AwgEndpointOptions) { value.S4 = maximumPaddingSize + 1 },
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

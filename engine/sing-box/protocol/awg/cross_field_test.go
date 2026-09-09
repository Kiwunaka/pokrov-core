package awg

import (
	"net/netip"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/sagernet/sing-box/option"
)

func TestAWG31CrossFieldRejectionBeforeDeviceCreation(t *testing.T) {
	for name, mutate := range map[string]func(*option.AwgEndpointOptions){
		"overlapping_headers": func(o *option.AwgEndpointOptions) { o.H2 = o.H1 },
		"oversized_handshake": func(o *option.AwgEndpointOptions) { o.S1 = 65535 },
		"oversized_transport": func(o *option.AwgEndpointOptions) { o.S4 = 65535 },
		"combined_transport_budget": func(o *option.AwgEndpointOptions) {
			o.MTU, o.S4 = 1408, 600
		},
		"expire_before_rekey": func(o *option.AwgEndpointOptions) {
			o.RekeyAfterTime, o.RejectAfterTime = "90-150", "100-120"
		},
		"immediate_receive_rekey": func(o *option.AwgEndpointOptions) {
			o.RekeyAfterTime, o.RejectAfterTime = "30", "40"
			o.KeepaliveTimeout, o.RekeyTimeout = "30", "10"
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := loadAWG31Fixture(t).Endpoint
			mutate(&options)
			if err := validateEndpointOptions(options); err == nil {
				t.Fatal("cross-field configuration must be rejected before creating a runtime device")
			}
		})
	}
}

func TestManagedAWGPacketBoundaryAndDefaultTimings(t *testing.T) {
	for name, fixture := range map[string]func(*testing.T) awgFixture{
		"awg2": loadFixture, "awg31": loadAWG31Fixture,
	} {
		t.Run(name, func(t *testing.T) {
			options := fixture(t).Endpoint
			options.MTU = 1408
			options.S4 = maximumManagedWirePacketSize - 1408 - awgdevice.MessageTransportSize
			if err := validateEndpointOptions(options); err != nil {
				t.Fatal("exact managed packet budget rejected")
			}
			options.S4++
			if err := validateEndpointOptions(options); err == nil {
				t.Fatal("one byte beyond managed packet budget accepted")
			}
		})
	}
	options := loadAWG31Fixture(t).Endpoint
	options.RekeyAfterTime, options.RejectAfterTime = "", ""
	options.RekeyTimeout, options.KeepaliveTimeout = "", ""
	if err := validateEndpointOptions(options); err != nil {
		t.Fatal("pinned default timing relationships rejected")
	}
	options.RejectAfterTime = "100"
	if err := validateEndpointOptions(options); err == nil {
		t.Fatal("explicit rejection before default rekey accepted")
	}
}

// Confirm the pinned upstream boundary before attributing a local-validator
// gap to runtime behavior. No Up call or packet is sent; the TUN's initial
// Up event is consumed before constructing the stopped upstream device.
func TestPinnedAWG31CrossFieldAcceptanceBoundary(t *testing.T) {
	for name, test := range map[string]struct {
		ipc      string
		rejected bool
	}{
		"header_overlap":     {ipc: "h1=100-200\nh2=150-250\n", rejected: true},
		"transport_overflow": {ipc: "s4=65535\n", rejected: false},
		"timing_inversion":   {ipc: "rekey_after_time=150\nreject_after_time=100\n", rejected: false},
	} {
		t.Run(name, func(t *testing.T) {
			tun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("198.18.0.1")}, nil, 1280)
			if err != nil {
				t.Fatal("create isolated upstream TUN")
			}
			select {
			case <-tun.Events():
			default:
				_ = tun.Close()
				t.Fatal("initial upstream TUN event was not available")
			}
			device := awgdevice.NewDevice(tun, conn.NewStdNetBind(), awgdevice.NewLogger(awgdevice.LogLevelSilent, ""))
			defer device.Close()
			if rejected := device.IpcSet(test.ipc) != nil; rejected != test.rejected {
				t.Fatalf("pinned upstream rejection changed: got %v, expected %v", rejected, test.rejected)
			}
		})
	}
}

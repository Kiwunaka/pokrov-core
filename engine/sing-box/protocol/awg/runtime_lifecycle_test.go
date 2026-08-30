package awg

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	awgtransport "github.com/sagernet/sing-box/transport/awg"
	M "github.com/sagernet/sing/common/metadata"
)

func TestSyntheticAWGRuntimeDeviceLifecycle(t *testing.T) {
	tests := []struct {
		name    string
		fixture func(*testing.T) awgFixture
	}{
		{name: "awg2", fixture: loadFixture},
		{name: "awg31", fixture: loadAWG31Fixture},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			fixture := testCase.fixture(t)
			options := fixture.Endpoint
			options.Peers = append([]option.AwgPeerOptions(nil), options.Peers...)
			options.Peers[0].Address = "127.0.0.1"
			options.Peers[0].Port = uint16(listener.LocalAddr().(*net.UDPAddr).Port)

			ipc, err := genIpcConfig(options)
			if err != nil {
				t.Fatalf("generate IPC config: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defaultDialer, err := dialer.NewDefault(ctx, option.DialerOptions{})
			if err != nil {
				t.Fatalf("create default dialer: %v", err)
			}
			device, err := awgtransport.NewDevice(
				ctx,
				log.NewNOPFactory().Logger(),
				defaultDialer,
				ipc,
				awgtransport.DeviceOpts{
					UseIntegratedTun: false,
					Address:          options.Address,
					AllowedIps:       options.Peers[0].AllowedIPs,
					ExcludedIps:      []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
					MTU:              options.MTU,
				},
			)
			if err != nil {
				t.Fatalf("create runtime device: %v", err)
			}
			defer device.Close()
			if err := device.Start(adapter.StartStateStart); err != nil {
				t.Fatalf("start runtime device: %v", err)
			}

			packetConn, err := device.ListenPacket(
				ctx,
				M.Socksaddr{
					Addr: netip.MustParseAddr("198.18.0.53"),
					Port: 53,
				},
			)
			if err != nil {
				t.Fatalf("open tunneled UDP connection: %v", err)
			}
			defer packetConn.Close()
			payload := []byte("pokrov-awg-synthetic-udp-probe")
			if writer, ok := packetConn.(interface {
				Write([]byte) (int, error)
			}); ok {
				if _, err := writer.Write(payload); err != nil {
					t.Fatalf("write tunneled UDP packet: %v", err)
				}
			} else {
				t.Fatal("tunneled UDP connection does not implement net.Conn write")
			}

			if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			outerPacket := make([]byte, 4096)
			n, _, err := listener.ReadFromUDP(outerPacket)
			if err != nil {
				t.Fatalf("read local AWG handshake packet: %v", err)
			}
			if n == 0 {
				t.Fatal("AWG runtime emitted an empty outer packet")
			}
			if bytes.Contains(outerPacket[:n], payload) {
				t.Fatal("AWG runtime exposed the synthetic inner payload in the outer packet")
			}

			if err := device.Close(); err != nil {
				t.Fatalf("close runtime device: %v", err)
			}
		})
	}
}

package awg

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type readStartedTun struct {
	tunAdapter
	reading chan struct{}
	once    sync.Once
}

func (t *readStartedTun) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	t.once.Do(func() { close(t.reading) })
	return t.tunAdapter.Read(packets, sizes, offset)
}

func TestFirstPacketUsesConfiguredTransportPadding(t *testing.T) {
	ctx := context.Background()
	var keys [2]*ecdh.PrivateKey
	var devices [2]*device.Device
	var tuns [2]*networkTun
	var ports [2]uint16
	addresses := [2]netip.Addr{netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")}
	for i := range devices {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("generate synthetic key")
		}
		keys[i] = key
		tun, err := newNetworkTun([]netip.Prefix{netip.PrefixFrom(addresses[i], 32)}, 1408)
		if err != nil {
			t.Fatal(err)
		}
		tuns[i] = tun.(*networkTun)
		observed := &readStartedTun{tunAdapter: tun, reading: make(chan struct{})}
		dial, err := dialer.NewDefault(ctx, option.DialerOptions{})
		if err != nil {
			t.Fatal(err)
		}
		bind := newBind(ctx, dial).(*bind_adapter)
		devices[i] = device.NewDevice(observed, bind, newSafeDeviceLogger(log.NewNOPFactory().Logger()))
		t.Cleanup(devices[i].Close)
		select {
		case <-observed.reading:
		case <-time.After(time.Second):
			t.Fatal("upstream TUN reader did not start")
		}
		// NewDevice starts Read before its caller applies IPC. Hold that exact
		// ordering deterministically, using only ephemeral synthetic material.
		if err := devices[i].IpcSet("private_key=" + hex.EncodeToString(key.Bytes()) + "\ns4=25\n"); err != nil {
			t.Fatal("configure synthetic device")
		}
		if err := tun.Start(); err != nil {
			t.Fatal(err)
		}
		if err := devices[i].Up(); err != nil {
			t.Fatal("start synthetic device")
		}
		ports[i], err = packetConnPort(bind.conn4)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range devices {
		peer := i ^ 1
		config := fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s/32\n",
			hex.EncodeToString(keys[peer].PublicKey().Bytes()), ports[peer], addresses[peer])
		if err := devices[i].IpcSet(config); err != nil {
			t.Fatal("configure synthetic peer")
		}
	}
	serverAddress := netip.AddrPortFrom(addresses[1], 53)
	server, err := tuns[1].conn.ListenUDPAddrPort(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := tuns[0].DialContext(ctx, "udp", M.SocksaddrFromNetIP(serverAddress))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("first-packet")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	server.SetReadDeadline(time.Now().Add(time.Second))
	n, _, firstErr := server.ReadFrom(buffer)
	firstArrived := firstErr == nil && string(buffer[:n]) == "first-packet"
	if _, err := client.Write([]byte("control-packet")); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = server.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "control-packet" {
		t.Fatal("synthetic control packet did not arrive")
	}
	if !firstArrived {
		t.Fatal("first UDP packet was lost after IPC set S4; second control packet arrived")
	}
}

func TestFailedIPCConfigurationClosesWaitingTUNReader(t *testing.T) {
	ctx := context.Background()
	dial, err := dialer.NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewDevice(ctx, log.NewNOPFactory().Logger(), dial, "invalid_option=1\n", DeviceOpts{
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}, MTU: 1408,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- device.Start(adapter.StartStateStart) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("invalid IPC configuration was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("failed IPC configuration left the TUN reader blocked")
	}
}

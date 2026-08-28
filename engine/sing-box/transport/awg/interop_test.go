package awg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/curve25519"
)

func TestBindAdapterInteroperatesWithPinnedAWGPeer(t *testing.T) {
	tests := []struct {
		name       string
		clientAddr netip.Addr
		serverAddr netip.Addr
		settings   string
	}{
		{
			name:       "awg2",
			clientAddr: netip.MustParseAddr("10.78.2.2"),
			serverAddr: netip.MustParseAddr("10.78.2.1"),
			settings: strings.Join([]string{
				"jc=4",
				"jmin=40",
				"jmax=70",
				"h1=1000001",
				"h2=1000002",
				"h3=1000003",
				"h4=1000004",
			}, "\n"),
		},
		{
			name:       "awg31",
			clientAddr: netip.MustParseAddr("10.78.31.2"),
			serverAddr: netip.MustParseAddr("10.78.31.1"),
			settings: strings.Join([]string{
				"jc=6",
				"jmin=48",
				"jmax=96",
				"s1=16",
				"s2=16",
				"s3=16",
				"s4=16",
				"h1=1100001-1100099",
				"h2=1200001-1200099",
				"h3=1300001-1300099",
				"h4=1400001-1400099",
				"i1=<t><r 16><b 0xdeadbeef>",
				"header_protection_key=0202020202020202020202020202020202020202020202020202020202020202",
				"content_padding_addition=16-96",
				"rekey_after_time=90-150",
				"rekey_timeout=4-8",
				"reject_after_time=180-240",
				"keepalive_timeout=8-14",
				"max_handshake_attempts=12-24",
				"random_trailers=true",
			}, "\n"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runPinnedPeerInterop(t, test.clientAddr, test.serverAddr, test.settings)
		})
	}
}

func runPinnedPeerInterop(t *testing.T, clientAddr, serverAddr netip.Addr, settings string) {
	t.Helper()

	clientPrivate, clientPublic := generateInteropKeyPair(t)
	serverPrivate, serverPublic := generateInteropKeyPair(t)

	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverAddr}, nil, 1408)
	if err != nil {
		t.Fatal("create pinned peer netstack TUN failed")
	}
	serverDevice := awgdevice.NewDevice(
		serverTun,
		conn.NewStdNetBind(),
		awgdevice.NewLogger(awgdevice.LogLevelError, ""),
	)
	t.Cleanup(serverDevice.Close)

	serverIPC := strings.Join([]string{
		settings,
		"private_key=" + hex.EncodeToString(serverPrivate),
		"listen_port=0",
		"replace_peers=true",
		"public_key=" + hex.EncodeToString(clientPublic),
		"protocol_version=1",
		"replace_allowed_ips=true",
		"allowed_ip=" + clientAddr.String() + "/32",
	}, "\n") + "\n"
	if err := serverDevice.IpcSet(serverIPC); err != nil {
		t.Fatal("configure pinned peer failed")
	}
	if err := serverDevice.Up(); err != nil {
		t.Fatal("start pinned peer failed")
	}
	serverState, err := serverDevice.IpcGet()
	if err != nil {
		t.Fatal("read pinned peer state failed")
	}
	serverPort, err := interopListenPort(serverState)
	if err != nil {
		t.Fatal("read pinned peer listen port failed")
	}

	clientIPC := strings.Join([]string{
		settings,
		"private_key=" + hex.EncodeToString(clientPrivate),
		"replace_peers=true",
		"public_key=" + hex.EncodeToString(serverPublic),
		"protocol_version=1",
		"endpoint=127.0.0.1:" + strconv.FormatUint(uint64(serverPort), 10),
		"replace_allowed_ips=true",
		"allowed_ip=" + serverAddr.String() + "/32",
	}, "\n") + "\n"
	clientDevice, err := NewDevice(
		context.Background(),
		log.NewNOPFactory().Logger(),
		interopDialer{},
		clientIPC,
		DeviceOpts{
			Address:    []netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
			AllowedIps: []netip.Prefix{netip.PrefixFrom(serverAddr, 32)},
			MTU:        1408,
		},
	)
	if err != nil {
		t.Fatal("create POKROV AWG device failed")
	}
	t.Cleanup(func() { _ = clientDevice.Close() })
	if err := clientDevice.Start(adapter.StartStateStart); err != nil {
		t.Fatal("start POKROV AWG device failed")
	}

	const servicePort = 18731
	listener, err := serverNet.ListenTCPAddrPort(netip.AddrPortFrom(serverAddr, servicePort))
	if err != nil {
		t.Fatal("start pinned peer inner listener failed")
	}
	t.Cleanup(func() { _ = listener.Close() })

	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
		payload := make([]byte, len("pokrov-awg-interop"))
		if _, readErr := io.ReadFull(connection, payload); readErr != nil {
			serverResult <- readErr
			return
		}
		_, writeErr := connection.Write(payload)
		serverResult <- writeErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := clientDevice.DialContext(
		ctx,
		N.NetworkTCP,
		M.Socksaddr{Addr: serverAddr, Port: servicePort},
	)
	if err != nil {
		t.Fatal("POKROV AWG inner TCP dial failed")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))

	want := []byte("pokrov-awg-interop")
	if _, err := connection.Write(want); err != nil {
		t.Fatal("POKROV AWG inner TCP write failed")
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(connection, got); err != nil {
		t.Fatal("POKROV AWG inner TCP read failed")
	}
	if string(got) != string(want) {
		t.Fatal("POKROV AWG inner TCP payload mismatch")
	}
	if err := <-serverResult; err != nil {
		t.Fatal("pinned peer inner TCP exchange failed")
	}
}

func generateInteropKeyPair(t *testing.T) (privateKey, publicKey []byte) {
	t.Helper()
	privateKey = make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal("generate ephemeral AWG private key failed")
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal("derive ephemeral AWG public key failed")
	}
	return privateKey, publicKey
}

func interopListenPort(state string) (uint16, error) {
	for _, line := range strings.Split(state, "\n") {
		value, found := strings.CutPrefix(line, "listen_port=")
		if !found {
			continue
		}
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return 0, errors.New("invalid allocated listen port")
		}
		return uint16(port), nil
	}
	return 0, errors.New("allocated listen port is missing")
}

type interopDialer struct{}

func (interopDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func (interopDialer) ListenPacket(
	ctx context.Context,
	destination M.Socksaddr,
) (net.PacketConn, error) {
	network := "udp4"
	if destination.Addr.Is6() {
		network = "udp6"
	}
	return (&net.ListenConfig{}).ListenPacket(ctx, network, destination.String())
}

var _ N.Dialer = interopDialer{}

func TestInteropListenPortRejectsUnsafeState(t *testing.T) {
	for _, state := range []string{"", "listen_port=0\n", "listen_port=invalid\n"} {
		if _, err := interopListenPort(state); err == nil {
			t.Fatalf("accepted invalid listen port state %q", fmt.Sprintf("%x", state))
		}
	}
}

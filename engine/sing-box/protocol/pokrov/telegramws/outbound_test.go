package telegramws

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type testOutbound struct{ outbound.Adapter }

func (o *testOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("test VPN dial")
}
func (o *testOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test VPN packet")
}

type testManager struct {
	adapter.OutboundManager
	values map[string]adapter.Outbound
}

func (m *testManager) Outbound(tag string) (adapter.Outbound, bool) {
	value, found := m.values[tag]
	return value, found
}

type capturedConnection struct {
	dialer  N.Dialer
	payload []byte
}
type captureManager struct {
	adapter.ConnectionManager
	size   int
	result chan capturedConnection
}

func (m *captureManager) NewConnection(_ context.Context, dialer N.Dialer, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	payload := make([]byte, m.size)
	_, err := io.ReadFull(conn, payload)
	m.result <- capturedConnection{dialer, payload}
	onClose(err)
}

type failedDialer struct{ calls atomic.Int32 }

func (d *failedDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("synthetic gateway unreachable")
}
func (d *failedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errScope
}

func testRuntime(size int) (*Outbound, *datacenter, *captureManager, *failedDialer) {
	dc := &datacenter{host: "kws2.web.telegram.org", address: M.ParseSocksaddr("149.154.167.220:443")}
	vpn := &testOutbound{outbound.NewAdapter("vless", "vpn", []string{N.NetworkTCP}, nil)}
	capture := &captureManager{size: size, result: make(chan capturedConnection, 1)}
	gateway := &failedDialer{}
	h := &Outbound{vpn: vpn, connection: capture, dialer: gateway,
		addresses: map[netip.Addr]*datacenter{netip.MustParseAddr("149.154.167.50"): dc},
		flows:     make(map[net.Conn]context.CancelFunc)}
	return h, dc, capture, gateway
}

func sendClient(t *testing.T, h *Outbound, payload []byte, destination M.Socksaddr) {
	t.Helper()
	client, runtime := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		h.NewConnection(context.Background(), runtime,
			adapter.InboundContext{Destination: destination}, nil)
		close(done)
	}()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("flow did not finish")
	}
}

func testInitialization(t *testing.T) ([]byte, cipher.Stream, cipher.Stream) {
	t.Helper()
	initial := make([]byte, 64)
	for {
		if _, err := rand.Read(initial); err != nil {
			t.Fatal(err)
		}
		if initial[0] != 0xef && binary.LittleEndian.Uint32(initial[4:8]) != 0 {
			break
		}
	}
	binary.LittleEndian.PutUint32(initial[56:60], 0xeeeeeeee)
	reversed := make([]byte, 64)
	for i := range initial {
		reversed[i] = initial[63-i]
	}
	encBlock, _ := aes.NewCipher(initial[8:40])
	decBlock, _ := aes.NewCipher(reversed[8:40])
	enc := cipher.NewCTR(encBlock, initial[40:56])
	dec := cipher.NewCTR(decBlock, reversed[40:56])
	encrypted := make([]byte, 64)
	enc.XORKeyStream(encrypted, initial)
	copy(initial[56:], encrypted[56:])
	return initial, enc, dec
}

func TestTLSSetupFailureReplaysOriginalBytesAndUsesVPNForNextFlow(t *testing.T) {
	initial, _, _ := testInitialization(t)
	payload := append(initial, bytes.Repeat([]byte{0x87}, 20)...)
	h, dc, capture, gateway := testRuntime(len(payload))
	destination := M.ParseSocksaddr("149.154.167.50:443")
	for i := 0; i < 2; i++ {
		sendClient(t, h, payload, destination)
		result := <-capture.result
		if result.dialer != h.vpn || !bytes.Equal(result.payload, payload) {
			t.Fatal("VPN did not retain the original byte stream")
		}
	}
	if gateway.calls.Load() != 1 || !dc.unavailable {
		t.Fatal("failed WSS path was retried by the next flow")
	}
}

func TestUnsupportedInitializationAndOutOfScopeDestinationStayInVPN(t *testing.T) {
	payload := bytes.Repeat([]byte{0x77}, 80)
	h, _, capture, gateway := testRuntime(len(payload))
	sendClient(t, h, payload, M.ParseSocksaddr("149.154.167.50:443"))
	if result := <-capture.result; result.dialer != h.vpn || !bytes.Equal(result.payload, payload) {
		t.Fatal("unsupported stream changed")
	}
	initial, _, _ := testInitialization(t)
	capture.size = len(initial)
	sendClient(t, h, initial, M.ParseSocksaddr("1.1.1.1:443"))
	if result := <-capture.result; result.dialer != h.vpn {
		t.Fatal("out-of-scope destination used WSS")
	}
	if gateway.calls.Load() != 0 {
		t.Fatal("unauthorized WSS dial")
	}
}

type signaledReadConn struct {
	net.Conn
	started chan struct{}
}

func (c *signaledReadConn) Read(p []byte) (int, error) { close(c.started); return c.Conn.Read(p) }

func TestCloseInterruptsPendingInitialization(t *testing.T) {
	h, _, _, _ := testRuntime(0)
	client, runtime := net.Pipe()
	defer client.Close()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		h.NewConnection(context.Background(), &signaledReadConn{runtime, started},
			adapter.InboundContext{Destination: M.ParseSocksaddr("149.154.167.50:443")}, nil)
		close(done)
	}()
	<-started
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt initialization")
	}
}

type eofConn struct{ net.Conn }

func (c *eofConn) Read([]byte) (int, error) { return 0, io.EOF }

func TestGatewayBreakStopsNewOffloadWithoutReplayingActiveStream(t *testing.T) {
	h, dc, capture, gateway := testRuntime(64)
	client, raw := net.Pipe()
	defer client.Close()
	remote := &gatewayConn{Conn: &eofConn{raw}, raw: raw, failed: func() { h.markUnavailable(dc) }}
	if _, err := remote.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	if err := remote.Close(); err != nil {
		t.Fatal(err)
	}
	initial, _, _ := testInitialization(t)
	sendClient(t, h, initial, M.ParseSocksaddr("149.154.167.50:443"))
	if result := <-capture.result; result.dialer != h.vpn || gateway.calls.Load() != 0 {
		t.Fatal("broken WSS remained admitted")
	}
}

type protectManager struct {
	adapter.NetworkManager
	requests int
}

func (m *protectManager) InterfaceFinder() control.InterfaceFinder { return nil }
func (m *protectManager) AutoDetectInterface() bool                { return false }
func (m *protectManager) DefaultOptions() adapter.NetworkOptions   { return adapter.NetworkOptions{} }
func (m *protectManager) ProtectFunc() control.Func                { m.requests++; return nil }
func (m *protectManager) AutoRedirectOutputMarkFunc() control.Func { return nil }

func TestConstructorProtectsSocketAndRejectsSelectorWithDirect(t *testing.T) {
	vpn := &testOutbound{outbound.NewAdapter("vless", "vpn", nil, nil)}
	direct := &testOutbound{outbound.NewAdapter("direct", "direct", nil, nil)}
	selector := &testOutbound{outbound.NewAdapter("selector", "select", nil, []string{"vpn", "direct"})}
	manager := &testManager{values: map[string]adapter.Outbound{"vpn": vpn, "direct": direct, "select": selector}}
	if protectedFallback(manager, selector, make(map[string]bool)) {
		t.Fatal("selector's Direct child admitted as VPN fallback")
	}
	protect := &protectManager{}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.ConnectionManager](ctx, &captureManager{})
	ctx = service.ContextWith[adapter.NetworkManager](ctx, protect)
	options := option.PokrovTelegramWSOutboundOptions{VPNOutbound: "vpn", Datacenters: []option.PokrovTelegramWSDatacenter{
		{ID: 2, Addresses: []string{"149.154.167.50"}, WebsocketAddress: "149.154.167.220"},
	}}
	value, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "telegram", options)
	if err != nil {
		t.Fatal(err)
	}
	if protect.requests != 1 {
		t.Fatal("platform socket protection was not requested")
	}
	if err := value.(*Outbound).Start(); err != nil {
		t.Fatal(err)
	}
}

// Explicit opt-in: one unauthenticated req_pq_multi, then disconnect. No auth
// key, user account, messages, credentials, or payload bytes are printed.
func TestTelegramWSReqPQ(t *testing.T) {
	if os.Getenv("POKROV_TELEGRAM_WS_PROBE") != "1" {
		t.Skip("explicit Telegram transport probe not requested")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "kws2.web.telegram.org")
	if err != nil || len(addresses) == 0 {
		t.Fatal("Telegram gateway resolution failed")
	}
	logger := log.NewNOPFactory().Logger()
	connection := route.NewConnectionManager(logger)
	defer connection.Close()
	vpn := &testOutbound{outbound.NewAdapter("vless", "vpn", nil, nil)}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &testManager{values: map[string]adapter.Outbound{"vpn": vpn}})
	ctx = service.ContextWith[adapter.ConnectionManager](ctx, connection)
	value, err := NewOutbound(ctx, nil, logger, "telegram", option.PokrovTelegramWSOutboundOptions{
		VPNOutbound: "vpn", Datacenters: []option.PokrovTelegramWSDatacenter{
			{ID: 2, Addresses: []string{"149.154.167.50"}, WebsocketAddress: addresses[0].String()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := value.(*Outbound)
	defer h.Close()
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	remote, runtime := net.Pipe()
	defer remote.Close()
	if err := remote.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go h.NewConnection(ctx, runtime, adapter.InboundContext{
		Destination: M.ParseSocksaddr("149.154.167.50:443"),
		TLSFragment: true, TLSRecordFragment: true, TLSSpoof: "kws2.web.telegram.org",
	}, nil)
	initial, encrypt, decrypt := testInitialization(t)
	if !nativeObfuscatedInitialization(initial) {
		t.Fatal("native initialization rejected")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, 44)
	binary.LittleEndian.PutUint32(request, 40)
	now := time.Now()
	messageID := uint64(now.Unix())<<32 | (uint64(now.Nanosecond())<<32/1_000_000_000)&^3
	binary.LittleEndian.PutUint64(request[12:20], messageID)
	binary.LittleEndian.PutUint32(request[20:24], 20)
	binary.LittleEndian.PutUint32(request[24:28], 0xbe7e8ef1)
	copy(request[28:], nonce)
	encrypt.XORKeyStream(request, request)
	if _, err := remote.Write(append(initial, request...)); err != nil {
		t.Fatal("Telegram WSS write failed")
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(remote, header); err != nil {
		t.Fatal("Telegram WSS response failed")
	}
	decrypt.XORKeyStream(header, header)
	length := binary.LittleEndian.Uint32(header)
	if length < 40 || length > 4096 {
		t.Fatal("Telegram MTProto response length invalid")
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(remote, response); err != nil {
		t.Fatal("Telegram MTProto response incomplete")
	}
	decrypt.XORKeyStream(response, response)
	if binary.LittleEndian.Uint32(response[16:20]) != uint32(len(response)-20) ||
		binary.LittleEndian.Uint32(response[20:24]) != 0x05162463 || !bytes.Equal(response[24:40], nonce) {
		t.Fatal("Telegram resPQ did not match our request")
	}
}

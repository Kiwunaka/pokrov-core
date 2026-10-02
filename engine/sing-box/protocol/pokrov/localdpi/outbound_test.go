package localdpi

import (
	stdbufio "bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"github.com/sagernet/sing/service"
)

var testPayload = []byte("synthetic-client-payload")

type testDialer struct {
	calls atomic.Int32
	dial  func(context.Context) (net.Conn, error)
}

func (d *testDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	return d.dial(ctx)
}
func (d *testDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errScope
}

type testVPN struct {
	outbound.Adapter
	*testDialer
}

type testManager struct {
	adapter.OutboundManager
	values map[string]adapter.Outbound
}

func (m *testManager) Outbound(tag string) (adapter.Outbound, bool) {
	v, found := m.values[tag]
	return v, found
}

type protectManager struct {
	adapter.NetworkManager
	requests int
}

func (*protectManager) InterfaceFinder() control.InterfaceFinder { return nil }
func (*protectManager) AutoDetectInterface() bool                { return false }
func (*protectManager) DefaultOptions() adapter.NetworkOptions   { return adapter.NetworkOptions{} }
func (m *protectManager) ProtectFunc() control.Func              { m.requests++; return nil }
func (*protectManager) AutoRedirectOutputMarkFunc() control.Func { return nil }

func newRuntime(t *testing.T) (*Outbound, *testVPN, chan []byte) {
	t.Helper()
	payloads := make(chan []byte, 8)
	vpn := &testVPN{Adapter: outbound.NewAdapter("vless", "vpn", []string{N.NetworkTCP}, nil)}
	vpn.testDialer = &testDialer{dial: func(context.Context) (net.Conn, error) {
		remote, server := net.Pipe()
		go func() {
			defer server.Close()
			payload := make([]byte, len(testPayload))
			_, err := io.ReadFull(server, payload)
			if err == nil {
				payloads <- payload
			}
		}()
		return remote, nil
	}}
	connections := route.NewConnectionManager(log.NewNOPFactory().Logger())
	protect := &protectManager{}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &testManager{
		values: map[string]adapter.Outbound{"vpn": vpn},
	})
	ctx = service.ContextWith[adapter.ConnectionManager](ctx, connections)
	ctx = service.ContextWith[adapter.NetworkManager](ctx, protect)
	options := option.PokrovLocalDPIOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
		VPNOutbound:   "vpn", ServiceID: "synthetic-service",
	}
	value, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "local", options)
	if err != nil {
		t.Fatal("synthetic runtime construction failed")
	}
	h := value.(*Outbound)
	if protect.requests != 1 {
		t.Fatal("platform socket protection was not requested")
	}
	if err := h.Start(); err != nil {
		t.Fatal("synthetic VPN start failed")
	}
	t.Cleanup(func() { _ = h.Close(); _ = connections.Close() })
	return h, vpn, payloads
}

func startFlow(t *testing.T, h *Outbound, ctx context.Context, destination M.Socksaddr, cached bool) <-chan struct{} {
	t.Helper()
	client, conn := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	if cached {
		conn = bufio.NewCachedConn(conn, buf.As(bytes.Clone(testPayload)))
	}
	done := make(chan struct{})
	go h.NewConnection(ctx, conn, adapter.InboundContext{
		Network: N.NetworkTCP, Destination: destination,
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.21"), netip.MustParseAddr("192.0.2.22")},
	}, func(error) { close(done) })
	return done
}

func waitFlow(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("flow cleanup timed out")
	}
}

func expectPayload(t *testing.T, payloads <-chan []byte) {
	t.Helper()
	select {
	case payload := <-payloads:
		if !bytes.Equal(payload, testPayload) {
			t.Fatal("VPN did not receive original payload")
		}
	case <-time.After(time.Second):
		t.Fatal("VPN payload missing")
	}
}

func TestAdmissionIdentityDefaultAndIneligibleVPN(t *testing.T) {
	h, vpn, payloads := newRuntime(t)
	other, otherVPN, otherPayloads := newRuntime(t)
	if h.IsReady() || other.IsReady() || h.AdmissionID() == other.AdmissionID() || h.ServiceID() != other.ServiceID() {
		t.Fatal("runtime admission identity/default invalid")
	}
	waitFlow(t, startFlow(t, h, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), true))
	expectPayload(t, payloads)
	if h.AdmitAdmission(other.AdmissionID()) || !h.AdmitAdmission(h.AdmissionID()) || !other.AdmitAdmission(other.AdmissionID()) {
		t.Fatal("exact publication identity was not enforced")
	}
	waitFlow(t, startFlow(t, other, context.Background(), M.ParseSocksaddr("reserved.test:443"), true))
	expectPayload(t, otherPayloads)
	if h.WithdrawAdmission(other.AdmissionID()) || !h.WithdrawAdmission(h.AdmissionID()) ||
		h.AdmitAdmission(h.AdmissionID()) || !other.IsReady() {
		t.Fatal("withdraw affected another admission or reopened its own")
	}
	waitFlow(t, startFlow(t, h, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), true))
	expectPayload(t, payloads)
	if vpn.calls.Load() != 2 || otherVPN.calls.Load() != 1 {
		t.Fatal("unavailable/ineligible flow did not use exactly one VPN dial")
	}
}

func TestSOCKSConnectFailureHasNoPayloadAndOneVPNFallback(t *testing.T) {
	h, vpn, payloads := newRuntime(t)
	h.AdmitAdmission(h.AdmissionID())
	noPayload := make(chan bool, 1)
	raw := &testDialer{dial: func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := stdbufio.NewReader(server)
			_, err := socks5.ReadAuthRequest(reader)
			if err == nil {
				err = socks5.WriteAuthResponse(server, socks5.AuthResponse{Method: socks5.AuthTypeNotRequired})
			}
			var request socks5.Request
			if err == nil {
				request, err = socks5.ReadRequest(reader)
			}
			if err == nil && request.Command == socks5.CommandConnect {
				err = socks5.WriteResponse(server, socks5.Response{ReplyCode: socks5.ReplyCodeConnectionRefused,
					Bind: M.ParseSocksaddr("127.0.0.1:1080")})
			}
			var extra [1]byte
			n, readErr := reader.Read(extra[:])
			noPayload <- err == nil && n == 0 && readErr != nil
		}()
		return client, nil
	}}
	h.proxy = socks.NewClient(raw, M.ParseSocksaddr("127.0.0.1:1080"), socks.Version5, "", "")
	for i := 0; i < 2; i++ {
		waitFlow(t, startFlow(t, h, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), true))
		expectPayload(t, payloads)
	}
	if !<-noPayload || raw.calls.Load() != 1 || vpn.calls.Load() != 2 || h.IsReady() {
		t.Fatal("CONNECT failure leaked payload, retried offload, or repeated VPN dial")
	}
}

func TestWindowsPhysicalSetupFailureWithdrawsOnlyItsHolderAndUsesVPN(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("physical Windows admission is unavailable on this host")
	}
	h, vpn, payloads := newRuntime(t)
	other, _, _ := newRuntime(t)
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &testManager{values: map[string]adapter.Outbound{"vpn": vpn}})
	ctx = service.ContextWith[adapter.ConnectionManager](ctx, h.connection)
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &protectManager{})
	options := option.PokrovLocalDPIOutboundOptions{
		DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: "physical-fixture"}},
		WindowsDirect: true, VPNOutbound: "vpn", ServiceID: "windows-service",
	}
	value, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "windows-local", options)
	if err != nil {
		t.Fatal("physically bound Windows construction failed")
	}
	local := value.(*Outbound)
	t.Cleanup(func() { _ = local.Close() })
	if local.IsReady() || local.AdmissionID() == other.AdmissionID() || local.Start() != nil {
		t.Fatal("Windows runtime did not retain unpublished isolated admission")
	}
	if local.AdmitAdmission(other.AdmissionID()) || !local.AdmitAdmission(local.AdmissionID()) || !other.AdmitAdmission(other.AdmissionID()) {
		t.Fatal("Windows admission accepted the wrong holder")
	}
	physical := &testDialer{dial: func(context.Context) (net.Conn, error) { return nil, errors.New("synthetic physical setup failure") }}
	local.proxy = physical
	for i := 0; i < 2; i++ {
		waitFlow(t, startFlow(t, local, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), true))
		expectPayload(t, payloads)
	}
	if physical.calls.Load() != 1 || vpn.calls.Load() != 2 || local.IsReady() || !other.IsReady() {
		t.Fatal("physical failure retried offload or escaped the captured holder")
	}
	options.BindInterface = ""
	if _, err = NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "unbound", options); err == nil {
		t.Fatal("Windows physical mode accepted an unbound dialer")
	}
}

type fastConn struct {
	net.Conn
	writes       atomic.Int32
	bufferWrites atomic.Int32
}

func (c *fastConn) Write([]byte) (int, error) {
	c.writes.Add(1)
	return 1, errors.New("synthetic partial write")
}
func (c *fastConn) WriteBuffer(*buf.Buffer) error {
	c.bufferWrites.Add(1)
	return errors.New("unexpected buffer fast path")
}
func (c *fastConn) Upstream() any         { return c.Conn }
func (*fastConn) ReaderReplaceable() bool { return true }
func (*fastConn) WriterReplaceable() bool { return true }

func TestPartialWriteNoReplayAndObserverFastPathCleanup(t *testing.T) {
	h, vpn, payloads := newRuntime(t)
	h.AdmitAdmission(h.AdmissionID())
	remote, server := net.Pipe()
	defer server.Close()
	transport := &fastConn{Conn: remote}
	proxy := &testDialer{dial: func(context.Context) (net.Conn, error) { return transport, nil }}
	h.proxy = proxy
	waitFlow(t, startFlow(t, h, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), true))
	if transport.writes.Load() != 1 || transport.bufferWrites.Load() != 0 || vpn.calls.Load() != 0 || h.IsReady() {
		t.Fatal("partial write was replayed or observer bypassed")
	}
	waitFlow(t, startFlow(t, h, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), true))
	expectPayload(t, payloads)
	h.mu.Lock()
	remaining := len(h.flows)
	h.mu.Unlock()
	if proxy.calls.Load() != 1 || vpn.calls.Load() != 1 || remaining != 0 {
		t.Fatal("next flow did not use VPN or owned flow retained")
	}
}

func TestPendingCancelWithdrawAndRuntimeClose(t *testing.T) {
	h, vpn, _ := newRuntime(t)
	other, _, _ := newRuntime(t)
	h.AdmitAdmission(h.AdmissionID())
	other.AdmitAdmission(other.AdmissionID())
	started := make(chan struct{}, 3)
	proxy := &testDialer{dial: func(ctx context.Context) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	h.proxy = proxy
	ctx, cancel := context.WithCancel(context.Background())
	done := startFlow(t, h, ctx, M.ParseSocksaddr("192.0.2.20:443"), false)
	<-started
	cancel()
	waitFlow(t, done)
	if !h.IsReady() || vpn.calls.Load() != 0 {
		t.Fatal("client cancellation invalidated admission or retried VPN")
	}
	done = startFlow(t, h, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), false)
	<-started
	if h.WithdrawAdmission(other.AdmissionID()) || !h.WithdrawAdmission(h.AdmissionID()) {
		t.Fatal("withdraw identity invalid")
	}
	waitFlow(t, done)
	if h.IsReady() || !other.IsReady() || vpn.calls.Load() != 0 {
		t.Fatal("withdraw retried pending flow or affected other admission")
	}
	other.proxy = proxy
	done = startFlow(t, other, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), false)
	<-started
	_ = other.Close()
	waitFlow(t, done)
}

func TestWithdrawalClosesOnlyOffloadAndFencesCachedPayload(t *testing.T) {
	h, vpn, payloads := newRuntime(t)
	h.AdmitAdmission(h.AdmissionID())
	received := make(chan *closeConn, 2)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	holdingDial := func(context.Context) (net.Conn, error) {
		remote, peer := net.Pipe()
		tracked := &closeConn{Conn: remote}
		go func() {
			defer peer.Close()
			payload := make([]byte, len(testPayload))
			if _, err := io.ReadFull(peer, payload); err == nil && bytes.Equal(payload, testPayload) {
				received <- tracked
			}
			<-release
		}()
		return tracked, nil
	}
	h.proxy = &testDialer{dial: holdingDial}
	localDone := startFlow(t, h, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), true)
	var localRemote *closeConn
	select {
	case localRemote = <-received:
	case <-time.After(time.Second):
		t.Fatal("local stream did not start")
	}
	baseVPN := vpn.dial
	vpn.dial = holdingDial
	vpnDone := startFlow(t, h, context.Background(), M.ParseSocksaddr("ordinary.test:443"), true)
	var vpnRemote *closeConn
	select {
	case vpnRemote = <-received:
	case <-time.After(time.Second):
		t.Fatal("ordinary VPN stream did not start")
	}
	if !h.WithdrawAdmission(h.AdmissionID()) || !localRemote.closed.Load() || vpnRemote.closed.Load() {
		t.Fatal("withdrawal did not close only its offloaded socket")
	}
	waitFlow(t, localDone)
	select {
	case <-vpnDone:
		t.Fatal("withdrawal closed an ordinary VPN flow")
	default:
	}
	late := &fastConn{Conn: localRemote}
	observed := &observedConn{Conn: late, ctx: context.Background(), admission: &h.admission}
	if n, err := observed.Write(testPayload); n != 0 || err == nil || late.writes.Load() != 0 {
		t.Fatal("cached payload crossed terminal admission")
	}
	vpn.dial = baseVPN
	waitFlow(t, startFlow(t, h, context.Background(), M.ParseSocksaddr("192.0.2.20:443"), true))
	expectPayload(t, payloads)
	if vpn.calls.Load() != 2 || h.AdmitAdmission(h.AdmissionID()) {
		t.Fatal("withdrawn stream was replayed or admission reopened")
	}
}

type closeConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestOwnConnectTimeoutWithdrawsAndClosesLateSocketBeforeVPN(t *testing.T) {
	h, vpn, payloads := newRuntime(t)
	h.AdmitAdmission(h.AdmissionID())
	raw, peer := net.Pipe()
	defer peer.Close()
	late := &closeConn{Conn: raw}
	parent := context.Background()
	proxy := &testDialer{dial: func(ctx context.Context) (net.Conn, error) {
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > setupTimeout || parent.Err() != nil {
			t.Error("CONNECT did not receive its own bounded live-parent budget")
		}
		return late, context.DeadlineExceeded
	}}
	h.proxy = proxy
	baseDial := vpn.dial
	vpn.dial = func(ctx context.Context) (net.Conn, error) {
		if !late.closed.Load() {
			t.Error("late socket remained open during VPN fallback")
		}
		return baseDial(ctx)
	}
	waitFlow(t, startFlow(t, h, parent, M.ParseSocksaddr("192.0.2.20:443"), true))
	expectPayload(t, payloads)
	if h.IsReady() || h.AdmitAdmission(h.AdmissionID()) || proxy.calls.Load() != 1 || vpn.calls.Load() != 1 {
		t.Fatal("own timeout retained admission or repeated fallback")
	}
}

type responseConn struct {
	net.Conn
	read bool
}

func (c *responseConn) Read(p []byte) (int, error) {
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	return copy(p, []byte{1}), io.EOF
}
func (c *responseConn) Upstream() any         { return c.Conn }
func (*responseConn) ReaderReplaceable() bool { return true }

func TestObserverRemoteBytesEOFAndCancellation(t *testing.T) {
	var admission atomic.Uint32
	admission.Store(admissionReady)
	raw, peer := net.Pipe()
	_ = peer.Close()
	observed := &observedConn{Conn: &responseConn{Conn: raw}, ctx: context.Background(), admission: &admission}
	var result bytes.Buffer
	_, _ = bufio.Copy(&result, observed)
	if result.Len() != 1 || admission.Load() != admissionReady {
		t.Fatal("remote bytes were bypassed or ordinary EOF invalidated admission")
	}
	_ = observed.Close()
	observed = &observedConn{Conn: raw, ctx: context.Background(), admission: &admission}
	_, _ = observed.Read(make([]byte, 1))
	if admission.Load() != admissionFailed {
		t.Fatal("early remote EOF did not withdraw admission")
	}
	admission.Store(admissionReady)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	observed = &observedConn{Conn: raw, ctx: ctx, admission: &admission}
	_, _ = observed.Read(make([]byte, 1))
	if admission.Load() != admissionReady {
		t.Fatal("canceled read invalidated admission")
	}
}

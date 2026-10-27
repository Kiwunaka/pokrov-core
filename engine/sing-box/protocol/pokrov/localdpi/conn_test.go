package localdpi

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type observedTestConn struct {
	net.Conn
	readByte   bool
	writeError error
}

type packetTestConn struct {
	N.PacketConn
	closed atomic.Bool
	failed error
}

func (c *packetTestConn) Close() error                     { c.closed.Store(true); return nil }
func (c *packetTestConn) HandshakeFailure(err error) error { c.failed = err; return nil }

type packetTestManager struct {
	adapter.ConnectionManager
	dials atomic.Int32
}

func (m *packetTestManager) NewPacketConnection(_ context.Context, _ N.Dialer, _ N.PacketConn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	m.dials.Add(1)
}

func newPendingTestOutbound(manager adapter.ConnectionManager, deadline time.Time) *Outbound {
	withdraw, cancel := context.WithCancel(context.Background())
	return &Outbound{connection: manager, serviceID: "youtube", preferTCP: true, admissionID: "fixture",
		admissionResolved: make(chan struct{}), admissionDeadline: deadline,
		withdrawCtx: withdraw, withdrawCancel: cancel, flows: make(map[*flow]struct{})}
}

func TestYouTubeQUICWaitsForProofAndRetainsVPNFallback(t *testing.T) {
	manager := &packetTestManager{}
	metadata := adapter.InboundContext{Network: N.NetworkUDP,
		Destination: M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 443}}
	start := func(h *Outbound, ctx context.Context, conn *packetTestConn) chan struct{} {
		done := make(chan struct{})
		go func() { h.NewPacketConnection(ctx, conn, metadata, nil); close(done) }()
		return done
	}
	await := func(done <-chan struct{}) {
		t.Helper()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("pending QUIC did not wake")
		}
	}

	ready := newPendingTestOutbound(manager, time.Now().Add(time.Second))
	pending := &packetTestConn{}
	done := start(ready, context.Background(), pending)
	select {
	case <-done:
		t.Fatal("pending QUIC escaped before proof")
	case <-time.After(20 * time.Millisecond):
	}
	other := metadata
	other.Destination.Port = 8443
	ready.NewPacketConnection(context.Background(), &packetTestConn{}, other, nil)
	if manager.dials.Load() != 1 || !ready.AdmitAdmission("fixture") {
		t.Fatal("ordinary UDP waited or YouTube admission failed")
	}
	await(done)
	if !pending.closed.Load() || !errors.Is(pending.failed, syscall.ECONNREFUSED) || manager.dials.Load() != 1 {
		t.Fatal("proved YouTube QUIC was not rejected before VPN handoff")
	}

	failed := newPendingTestOutbound(manager, time.Now().Add(time.Second))
	fallback := &packetTestConn{}
	done = start(failed, context.Background(), fallback)
	if !failed.WithdrawAdmission("fixture") {
		t.Fatal("withdrawal failed")
	}
	await(done)
	if fallback.closed.Load() || manager.dials.Load() != 2 {
		t.Fatal("failed proof did not hand QUIC to the protected VPN")
	}

	expired := newPendingTestOutbound(manager, time.Now().Add(-time.Millisecond))
	expired.NewPacketConnection(context.Background(), &packetTestConn{}, metadata, nil)
	if manager.dials.Load() != 3 {
		t.Fatal("an expired holder restarted its wait")
	}

	stopped := newPendingTestOutbound(manager, time.Now().Add(time.Second))
	closed := &packetTestConn{}
	done = start(stopped, context.Background(), closed)
	select {
	case <-done:
		t.Fatal("QUIC did not wait before Stop")
	case <-time.After(20 * time.Millisecond):
	}
	if err := stopped.Close(); err != nil {
		t.Fatal(err)
	}
	await(done)
	if !closed.closed.Load() || manager.dials.Load() != 3 {
		t.Fatal("Stop left QUIC waiting or started a VPN flow")
	}
}

type admissionTestDialer struct {
	name   string
	events chan string
}

func (d *admissionTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	d.events <- d.name
	return nil, errors.New("synthetic dial failure")
}
func (d *admissionTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet dial")
}

type admissionTestVPN struct {
	adapter.Outbound
	dialer *admissionTestDialer
}

func (v *admissionTestVPN) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return v.dialer.DialContext(ctx, network, address)
}

func TestYouTubeTCPTriesAdmittedLocalBeforeVPNAndSharesDeadline(t *testing.T) {
	events := make(chan string, 4)
	metadata := adapter.InboundContext{Network: N.NetworkTCP,
		Destination: M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 443}}
	start := func(h *Outbound, ctx context.Context) <-chan struct{} {
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		done := make(chan struct{})
		go func() { h.NewConnection(ctx, client, metadata, nil); close(done) }()
		return done
	}
	setup := func(deadline time.Time) *Outbound {
		h := newPendingTestOutbound(nil, deadline)
		h.proxy = &admissionTestDialer{name: "local", events: events}
		h.vpn = &admissionTestVPN{dialer: &admissionTestDialer{name: "vpn", events: events}}
		return h
	}
	h := setup(time.Now().Add(time.Second))
	done := start(h, context.Background())
	select {
	case <-events:
		t.Fatal("TCP escaped before proof")
	case <-time.After(20 * time.Millisecond):
	}
	if !h.AdmitAdmission("fixture") {
		t.Fatal("admission failed")
	}
	readEvent := func() string {
		t.Helper()
		select {
		case event := <-events:
			return event
		case <-time.After(time.Second):
			t.Fatal("dial did not start")
			return ""
		}
	}
	if got := readEvent(); got != "local" {
		t.Fatalf("first dial: %s", got)
	}
	if got := readEvent(); got != "vpn" {
		t.Fatalf("fallback dial: %s", got)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed local proof did not finish")
	}

	expiring := setup(time.Now().Add(50 * time.Millisecond))
	done = start(expiring, context.Background())
	if got := readEvent(); got != "vpn" {
		t.Fatalf("expired holder dialed %s", got)
	}
	<-done
	done = start(expiring, context.Background())
	if got := readEvent(); got != "vpn" {
		t.Fatalf("later flow restarted the holder wait: %s", got)
	}
	<-done

	cancelled := setup(time.Now().Add(time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	done = start(cancelled, ctx)
	select {
	case <-done:
		t.Fatal("TCP did not wait before cancellation")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel left TCP waiting")
	}
	select {
	case <-events:
		t.Fatal("cancel started a local or VPN dial")
	default:
	}

	other := setup(time.Now().Add(time.Second))
	other.serviceID, other.preferTCP = "other", false
	done = start(other, context.Background())
	if got := readEvent(); got != "vpn" {
		t.Fatalf("ordinary service used %s", got)
	}
	<-done
}

func (c *observedTestConn) Read(p []byte) (int, error) {
	if c.readByte {
		c.readByte = false
		p[0] = 1
		return 1, nil
	}
	return 0, io.EOF
}

func (c *observedTestConn) Write(p []byte) (int, error) {
	if c.writeError != nil {
		return 0, c.writeError
	}
	return len(p), nil
}

func (*observedTestConn) Close() error { return nil }

func TestIdleLocalDpiEOFKeepsAdmissionAndUsedFlowFailureIsRetained(t *testing.T) {
	newConnection := func(remote *observedTestConn) (*Outbound, *observedConn) {
		withdraw, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		h := &Outbound{admissionID: "fixture", withdrawCtx: withdraw, withdrawCancel: cancel}
		h.admission.Store(admissionReady)
		return h, &observedConn{Conn: remote, ctx: context.Background(), owner: h}
	}
	buffer := make([]byte, 1)
	idle, idleConn := newConnection(&observedTestConn{})
	if _, err := idleConn.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatal("idle fixture did not close")
	}
	if !idle.IsReady() || idle.ReadObservation().FailureReason != "none" {
		t.Fatal("unused speculative socket retired the service")
	}
	_ = idleConn.Close()

	used, usedConn := newConnection(&observedTestConn{})
	_, _ = usedConn.Write([]byte{1})
	_, _ = usedConn.Read(buffer)
	if used.IsReady() || used.ReadObservation().FailureReason != "early_read" {
		t.Fatal("EOF after client payload lost its failed admission and closed reason")
	}
	used.failAdmission(failureConnectErrorIPv6)
	used.WithdrawAdmission("fixture")
	if observed := used.ReadObservation(); observed.State != "withdrawn" || observed.FailureReason != "early_read" {
		t.Fatal("later failures or withdrawal overwrote the first reason")
	}

	writeFailed, writeConn := newConnection(&observedTestConn{writeError: errors.New("synthetic private transport detail")})
	_, _ = writeConn.Write([]byte{1})
	if observed := writeFailed.ReadObservation(); observed.State != "failed" || observed.FailureReason != "early_write" {
		t.Fatal("write failure escaped the closed reason projection")
	}
	responded, respondedConn := newConnection(&observedTestConn{readByte: true})
	_, _ = respondedConn.Write([]byte{1})
	_, _ = respondedConn.Read(buffer)
	_, _ = respondedConn.Read(buffer)
	if !responded.IsReady() || responded.ReadObservation().FailureReason != "none" {
		t.Fatal("completed responding connection retired the service")
	}
}

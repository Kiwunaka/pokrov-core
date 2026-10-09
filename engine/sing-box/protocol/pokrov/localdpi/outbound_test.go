package localdpi

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type observationDialer struct {
	N.Dialer
	dial func(context.Context) (net.Conn, error)
}

func (d *observationDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx)
}

type observationVPN struct {
	outbound.Adapter
	observationDialer
}

type observationClosingConn struct {
	net.Conn
	closing chan struct{}
	release chan struct{}
}

func (c *observationClosingConn) Close() error {
	close(c.closing)
	<-c.release
	return c.Conn.Close()
}

type observationConnections struct {
	adapter.ConnectionManager
	t        *testing.T
	remotes  []net.Conn
	finishes []N.CloseHandlerFunc
}

func (m *observationConnections) NewConnection(ctx context.Context, dialer N.Dialer, _ net.Conn, metadata adapter.InboundContext, finish N.CloseHandlerFunc) {
	remote, err := dialer.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		m.t.Fatal(err)
	}
	m.remotes = append(m.remotes, remote)
	m.finishes = append(m.finishes, finish)
}

func TestObservationLocalWithdrawalThenFreshVPNHandoff(t *testing.T) {
	withdrawCtx, withdrawCancel := context.WithCancel(context.Background())
	connections := &observationConnections{t: t}
	h := &Outbound{
		admissionID: "captured-holder", connection: connections,
		withdrawCtx: withdrawCtx, withdrawCancel: withdrawCancel, flows: make(map[*flow]struct{}),
	}
	t.Cleanup(func() {
		_ = h.Close()
		for _, finish := range connections.finishes {
			finish(nil)
		}
	})
	if got := h.ReadObservation(); got != (Observation{State: "unpublished"}) {
		t.Fatalf("new holder observation: %+v", got)
	}
	if !h.AdmitAdmission(h.AdmissionID()) {
		t.Fatal("fresh holder was not admitted")
	}
	metadata := adapter.InboundContext{Network: N.NetworkTCP, Destination: M.Socksaddr{Addr: netip.MustParseAddr("203.0.113.1"), Port: 443}}

	// A late local socket from a canceled setup is closed without a handoff or
	// a VPN retry. It must not poison the admission or increment either count.
	canceledCtx, cancelSetup := context.WithCancel(context.Background())
	late, latePeer := net.Pipe()
	t.Cleanup(func() { _ = latePeer.Close() })
	h.proxy = &observationDialer{dial: func(context.Context) (net.Conn, error) { cancelSetup(); return late, nil }}
	canceledClient, canceledPeer := net.Pipe()
	t.Cleanup(func() { _ = canceledPeer.Close() })
	h.NewConnection(canceledCtx, canceledClient, metadata, nil)
	if got := h.ReadObservation(); got != (Observation{State: "ready"}) || len(connections.remotes) != 0 {
		t.Fatalf("canceled setup was counted or changed admission: %+v", got)
	}
	assertObservationPeerClosed(t, latePeer)

	localSocket, localPeer := net.Pipe()
	local := &observationClosingConn{Conn: localSocket, closing: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	releaseLocalClose := func() { releaseOnce.Do(func() { close(local.release) }) }
	t.Cleanup(releaseLocalClose)
	t.Cleanup(func() { _ = localPeer.Close() })
	h.proxy = &observationDialer{dial: func(context.Context) (net.Conn, error) { return local, nil }}
	localClient, localClientPeer := net.Pipe()
	t.Cleanup(func() { _ = localClientPeer.Close() })
	h.NewConnection(context.Background(), localClient, metadata, nil)
	if got := h.ReadObservation(); got != (Observation{State: "ready", LocalHandoffs: 1}) || len(connections.remotes) != 1 {
		t.Fatalf("local handoff was not measured: %+v", got)
	}

	// A transport failure after handoff changes the real latch and cannot replay
	// this stream through VPN. Its existing handoff remains counted.
	_ = localPeer.Close()
	if _, err := connections.remotes[0].Write([]byte("payload")); err == nil {
		t.Fatal("closed local peer accepted payload")
	}
	if got := h.ReadObservation(); got != (Observation{State: "failed", LocalHandoffs: 1}) || len(connections.remotes) != 1 {
		t.Fatalf("post-handoff failure was replayed or misreported: %+v", got)
	}
	var oldFlow *flow
	h.mu.Lock()
	for f := range h.flows {
		if f.local {
			oldFlow = f
		}
	}
	h.mu.Unlock()
	if oldFlow == nil {
		t.Fatal("local flow missing before withdrawal")
	}
	closed := make(chan struct{})
	go func() { oldFlow.close(); close(closed) }()
	<-local.closing
	withdrawn := make(chan bool, 1)
	go func() { withdrawn <- h.WithdrawAdmission(h.AdmissionID()) }()
	select {
	case <-withdrawn:
		t.Fatal("withdrawal completed before the competing local close")
	case <-time.After(50 * time.Millisecond):
	}
	releaseLocalClose()
	<-closed
	if !<-withdrawn {
		t.Fatal("current holder was not withdrawn")
	}
	assertObservationPeerClosed(t, localClientPeer)
	if got := h.ReadObservation(); got != (Observation{State: "withdrawn", WithdrawCompleted: true, LocalHandoffs: 1}) {
		t.Fatalf("completed withdrawal observation: %+v", got)
	}

	vpn, vpnPeer := net.Pipe()
	t.Cleanup(func() { _ = vpnPeer.Close() })
	h.vpn = &observationVPN{Adapter: outbound.NewAdapter(C.TypeVLESS, "vpn", []string{N.NetworkTCP}, nil),
		observationDialer: observationDialer{dial: func(context.Context) (net.Conn, error) { return vpn, nil }}}
	vpnClient, vpnClientPeer := net.Pipe()
	t.Cleanup(func() { _ = vpnClientPeer.Close() })
	h.NewConnection(context.Background(), vpnClient, metadata, nil)
	if got := h.ReadObservation(); got != (Observation{State: "withdrawn", WithdrawCompleted: true, LocalHandoffs: 1, VPNHandoffs: 1}) || len(connections.remotes) != 2 || connections.remotes[1] != vpn {
		t.Fatalf("fresh request did not hand off through VPN: %+v", got)
	}

	// Raw dialer calls are outside NewConnection handoffs.
	if _, err := h.DialContext(context.Background(), N.NetworkTCP, metadata.Destination); err != nil {
		t.Fatal(err)
	}
	if got := h.ReadObservation(); got.VPNHandoffs != 1 {
		t.Fatal("raw VPN dial was counted as a flow handoff")
	}
}

func assertObservationPeerClosed(t *testing.T, peer net.Conn) {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("old local socket stayed open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("old local socket was not closed before withdrawal returned")
	}
}

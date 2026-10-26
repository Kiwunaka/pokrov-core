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
	dials    int
	finishes []N.CloseHandlerFunc
	contexts []context.Context
}

func (m *packetTestManager) NewPacketConnection(ctx context.Context, _ N.Dialer, _ N.PacketConn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	m.dials++
	m.finishes = append(m.finishes, onClose)
	m.contexts = append(m.contexts, ctx)
}

func TestYouTubeQUICMovesToTCPOnlyWhileAdmitted(t *testing.T) {
	manager := &packetTestManager{}
	withdraw, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := &Outbound{connection: manager, preferTCP: true, admissionID: "fixture", withdrawCtx: withdraw,
		withdrawCancel: cancel, quicFlows: make(map[*packetFlow]struct{})}
	metadata := adapter.InboundContext{Network: N.NetworkUDP,
		Destination: M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 443}}
	oldQUIC := &packetTestConn{}
	h.NewPacketConnection(context.Background(), oldQUIC, metadata, nil)
	otherUDP := &packetTestConn{}
	other := metadata
	other.Destination.Port = 8443
	h.NewPacketConnection(context.Background(), otherUDP, other, nil)
	if manager.dials != 2 || oldQUIC.closed.Load() || otherUDP.closed.Load() {
		t.Fatal("pending proof changed the ordinary VPN path")
	}
	if !h.AdmitAdmission("fixture") || !oldQUIC.closed.Load() || manager.contexts[0].Err() == nil || otherUDP.closed.Load() {
		t.Fatal("admission did not retire only the pre-proof QUIC session")
	}
	manager.finishes[0](nil)
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		metadata.Destination.Addr = netip.MustParseAddr(ip)
		metadata.UDPConnect = true
		conn := &packetTestConn{}
		h.NewPacketConnection(context.Background(), conn, metadata, nil)
		if !conn.closed.Load() || !errors.Is(conn.failed, syscall.ECONNREFUSED) || manager.dials != 2 {
			t.Fatal("ready QUIC escaped rejection or opened a VPN connection")
		}
	}
	if h.ReadObservation().QUICRejected != 2 || h.ReadObservation().LocalHandoffs != 0 {
		t.Fatal("QUIC rejection was reported as a successful TCP handoff")
	}
	h.failAdmission(failureEarlyRead)
	afterFailure := &packetTestConn{}
	h.NewPacketConnection(context.Background(), afterFailure, metadata, nil)
	h.WithdrawAdmission("fixture")
	afterWithdrawal := &packetTestConn{}
	h.NewPacketConnection(context.Background(), afterWithdrawal, metadata, nil)
	if manager.dials != 4 || afterFailure.closed.Load() || afterWithdrawal.closed.Load() || otherUDP.closed.Load() {
		t.Fatal("failed or withdrawn admission blocked the VPN fallback")
	}
	ordinary := &Outbound{connection: manager}
	ordinary.admission.Store(admissionReady)
	ordinary.NewPacketConnection(context.Background(), &packetTestConn{}, metadata, nil)
	if manager.dials != 5 {
		t.Fatal("another local-DPI service inherited YouTube's TCP policy")
	}
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

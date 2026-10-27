package localdpi

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestWindowsRuntimeRetryReplacesBatchWithoutInterruptingVPN(t *testing.T) {
	manager := &packetTestManager{}
	events := make(chan string, 2)
	makeHolder := func(tag, id string) *Outbound {
		h := newPendingTestOutbound(manager, time.Now().Add(5*time.Second))
		h.Adapter = outbound.NewAdapter(Type, tag, nil, nil)
		h.admissionID, h.windowsDirect, h.runtimeCtx = id, true, context.Background()
		h.vpn = &admissionTestVPN{dialer: &admissionTestDialer{name: "vpn", events: events}}
		if !h.AdmitAdmission(id) {
			t.Fatal("fixture admission failed")
		}
		t.Cleanup(func() { _ = h.Close() })
		return h
	}
	oldA, oldB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	a, b := makeHolder("a", oldA), makeHolder("b", oldB)
	a.failAdmission(oldA, failureEarlyRead)
	local, localPeer := net.Pipe()
	vpn, vpnPeer := net.Pipe()
	t.Cleanup(func() { _ = localPeer.Close(); _ = vpnPeer.Close() })
	localCtx, cancelLocal := context.WithCancel(context.Background())
	vpnCtx, cancelVPN := context.WithCancel(context.Background())
	a.flows[&flow{client: local, cancel: cancelLocal, local: true}] = struct{}{}
	a.flows[&flow{client: vpn, cancel: cancelVPN}] = struct{}{}
	oldObserver := &observedConn{Conn: &observedTestConn{}, ctx: context.Background(), owner: a, admissionID: oldA}

	if ids, ok := PrepareWindowsRetry([]*Outbound{a, b}, []string{oldA, strings.Repeat("c", 32)}); ok || len(ids) != 0 {
		t.Fatal("stale batch accepted")
	}
	if a.AdmissionID() != oldA || b.AdmissionID() != oldB || a.ReadObservation().State != "failed" || !b.IsReady() || localCtx.Err() != nil {
		t.Fatal("rejected batch changed a holder or local flow")
	}
	ids, ok := PrepareWindowsRetry([]*Outbound{a, b}, []string{oldA, oldB})
	if !ok || len(ids) != 2 || ids[0] == oldA || ids[1] == oldB || ids[0] == ids[1] || a.IsReady() || b.IsReady() {
		t.Fatal("retry did not create two fresh unpublished holders")
	}
	if localCtx.Err() == nil || vpnCtx.Err() != nil {
		t.Fatal("retry did not close only the local flow")
	}
	_ = localPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := localPeer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("old local socket remained open")
	}
	_ = vpnPeer.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = vpn.Write([]byte{1}) }()
	if n, err := vpnPeer.Read(make([]byte, 1)); err != nil || n != 1 {
		t.Fatal("existing VPN socket was interrupted")
	}
	if a.AdmitAdmission(oldA) || a.WithdrawAdmission(oldA) {
		t.Fatal("old identity affected the fresh holder")
	}
	metadata := adapter.InboundContext{Network: N.NetworkTCP, Destination: M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 443}}
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	go a.NewConnection(context.Background(), client, metadata, nil)
	select {
	case event := <-events:
		if event != "vpn" {
			t.Fatal("retry proof used local TCP")
		}
	case <-time.After(time.Second):
		t.Fatal("TCP waited for retry proof")
	}
	metadata.Network = N.NetworkUDP
	packetDone := make(chan struct{})
	go func() {
		a.NewPacketConnection(context.Background(), &packetTestConn{}, metadata, nil)
		close(packetDone)
	}()
	select {
	case <-packetDone:
		if manager.dials.Load() != 1 {
			t.Fatal("UDP did not use VPN during retry proof")
		}
	case <-time.After(time.Second):
		t.Fatal("UDP waited for retry proof")
	}
	if !a.AdmitAdmission(ids[0]) || !b.AdmitAdmission(ids[1]) {
		t.Fatal("fresh proof could not admit new holders")
	}
	oldObserver.observe(errors.New("late read"), failureEarlyRead)
	if !a.IsReady() || a.ReadObservation().FailureReason != "none" {
		t.Fatal("old flow observer failed the new generation")
	}
	a.failAdmission(ids[0], failureEarlyRead)
	if _, ok := PrepareWindowsRetry([]*Outbound{a, b}, ids); ok {
		t.Fatal("retry budget exceeded")
	}
}

//go:build with_clash_api && with_conntrack

package hcore

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kiwunaka/POKROV-core/v2/config"
	"github.com/Kiwunaka/POKROV-core/v2/hcommon"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service/filemanager"
)

func TestSelectOutboundRejectsUnavailableRuntime(t *testing.T) {
	h := &PokrovInstance{}
	for _, request := range []*SelectOutboundRequest{
		nil,
		{},
		{GroupTag: "candidates", OutboundTag: "b"},
	} {
		response, err := h.SelectOutbound(request)
		if err == nil || response.Code != hcommon.ResponseCode_FAILED {
			t.Fatal("selection reported success without a running selector")
		}
	}
	if err := h.resetNetwork(); err == nil {
		t.Fatal("network reset reported success without a runtime")
	}
}

func TestSelectOutboundAndNetworkResetKeepRuntime(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	root := t.TempDir()
	ctx = filemanager.WithDefault(ctx, root, root, os.Getuid(), os.Getgid())
	options, err := config.ReadSingOptions(ctx, &config.ReadOptions{Content: `{
	 "log":{"disabled":true},
	 "inbounds":[{"type":"mixed","tag":"local","listen":"127.0.0.1","listen_port":0,"users":[{"username":"test","password":"test"}]}],
	 "outbounds":[
	  {"type":"selector","tag":"candidates","outbounds":["a","b"],"default":"a","interrupt_exist_connections":true},
	  {"type":"direct","tag":"a","inet4_bind_address":"127.0.0.1"},
	  {"type":"direct","tag":"b","inet4_bind_address":"127.0.0.2"}
	 ],
	 "route":{"final":"candidates"}
	}`})
	if err != nil {
		t.Fatal(err)
	}
	started, err := NewService(ctx, *options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = started.Close() })
	h := &PokrovInstance{StartedService: started}
	instance, runtime, runtimeContext := h.Instance(), h.Box(), h.Context()
	inbound, _ := runtime.Inbound().Get("local")
	outbound, _ := runtime.Outbound().Outbound("candidates")
	selector := outbound.(*group.Selector)
	assertIdentity := func() {
		t.Helper()
		currentInbound, _ := h.Box().Inbound().Get("local")
		if h.StartedService != started || h.Instance() != instance || h.Box() != runtime || h.Context() != runtimeContext || currentInbound != inbound {
			t.Fatal("selection or network reset replaced the running service or its inbound")
		}
	}
	physicalContext := interrupt.ContextWithIsExternalConnection(context.Background())

	tcpOrigin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpOrigin.Close() })
	go func() {
		for {
			conn, err := tcpOrigin.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.WriteString(conn, conn.RemoteAddr().(*net.TCPAddr).IP.String()+"\n")
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	udpOrigin, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpOrigin.Close() })
	go func() {
		var payload [16]byte
		for {
			_, source, err := udpOrigin.ReadFrom(payload[:])
			if err != nil {
				return
			}
			_, _ = udpOrigin.WriteTo([]byte(source.(*net.UDPAddr).IP.String()), source)
		}
	}()
	tcpSession := func(expectedSource string) net.Conn {
		t.Helper()
		conn, err := selector.DialContext(physicalContext, "tcp", M.ParseSocksaddr(tcpOrigin.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		source, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil || strings.TrimSpace(source) != expectedSource {
			t.Fatalf("TCP used the wrong candidate path: source=%q err=%v", source, err)
		}
		return conn
	}
	udpSession := func(expectedSource string) net.PacketConn {
		t.Helper()
		conn, err := selector.ListenPacket(physicalContext, M.ParseSocksaddr(udpOrigin.LocalAddr().String()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.WriteTo([]byte("path"), udpOrigin.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		var reply [16]byte
		n, _, err := conn.ReadFrom(reply[:])
		if err != nil || string(reply[:n]) != expectedSource {
			t.Fatalf("UDP used the wrong candidate path: source=%q err=%v", reply[:n], err)
		}
		return conn
	}
	assertClosed := func(tcp net.Conn, udp net.PacketConn) {
		t.Helper()
		var payload [1]byte
		_ = tcp.SetReadDeadline(time.Now().Add(time.Second))
		_, tcpErr := tcp.Read(payload[:])
		_ = udp.SetReadDeadline(time.Now().Add(time.Second))
		_, _, udpErr := udp.ReadFrom(payload[:])
		for _, err := range []error{tcpErr, udpErr} {
			if err == nil {
				t.Fatal("old candidate session remained open")
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("old candidate session survived until the read deadline")
			}
		}
	}
	selectCandidate := func(tag string) {
		t.Helper()
		response, err := h.SelectOutbound(&SelectOutboundRequest{GroupTag: "candidates", OutboundTag: tag})
		if err != nil || response.Code != hcommon.ResponseCode_OK || selector.Now() != tag {
			t.Fatalf("candidate selection failed: %v", err)
		}
		assertIdentity()
	}
	oldTCP, oldUDP := tcpSession("127.0.0.1"), udpSession("127.0.0.1")
	selectCandidate("a") // Selecting the current candidate must preserve its sessions.
	if _, err := oldTCP.Write([]byte("same")); err != nil {
		t.Fatal(err)
	}
	var echo [4]byte
	if _, err := io.ReadFull(oldTCP, echo[:]); err != nil || string(echo[:]) != "same" {
		t.Fatal("reselecting the current candidate interrupted its TCP session")
	}
	selectCandidate("b")
	assertClosed(oldTCP, oldUDP)
	newTCP, newUDP := tcpSession("127.0.0.2"), udpSession("127.0.0.2")
	for _, request := range []*SelectOutboundRequest{
		{GroupTag: "missing", OutboundTag: "a"},
		{GroupTag: "a", OutboundTag: "b"},
		{GroupTag: "candidates", OutboundTag: "missing"},
	} {
		response, err := h.SelectOutbound(request)
		if err == nil || response.Code != hcommon.ResponseCode_FAILED || selector.Now() != "b" {
			t.Fatal("invalid selection changed the active candidate or reported success")
		}
	}
	if err := h.resetNetwork(); err != nil {
		t.Fatal(err)
	}
	assertIdentity()
	assertClosed(newTCP, newUDP)
	if selector.Now() != "b" {
		t.Fatal("network reset discarded the active candidate")
	}
	_ = tcpSession("127.0.0.2")
	_ = udpSession("127.0.0.2")
	selectCandidate("a")
	_ = tcpSession("127.0.0.1")
}

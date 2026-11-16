package slipstream

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type tcpProbeDialer struct {
	N.Dialer
	handle        func(net.Conn)
	udpConnection net.Conn
	wait          sync.WaitGroup
	udp           atomic.Int32
}

func (d *tcpProbeDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		d.udp.Add(1)
		if d.udpConnection != nil {
			return d.udpConnection, nil
		}
		return nil, N.ErrUnknownNetwork
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	d.wait.Add(1)
	go func() { defer d.wait.Done(); defer server.Close(); d.handle(server) }()
	return client, nil
}

func TestTCPDNSRequiresConnectionReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		buffer := make([]byte, 4096)
		size, err := server.Read(buffer)
		if err != nil {
			return
		}
		var query dns.Msg
		if query.Unpack(buffer[:size]) != nil {
			return
		}
		reply, _ := new(dns.Msg).SetReply(&query).Pack()
		if _, err := server.Write(reply); err != nil {
			return
		}
		io.Copy(server, server)
	}()
	dialer := &tcpProbeDialer{udpConnection: client, handle: func(connection net.Conn) {
		wire := &dns.Conn{Conn: connection}
		query, err := wire.ReadMsg()
		if err == nil {
			wire.WriteMsg(new(dns.Msg).SetReply(query))
		}
		// Router resolvers can close TCP after their first successful reply.
	}}
	h := &Outbound{ctx: ctx, dialer: dialer, tunnelConfig: &tunnelConfig{
		domain: "t.example.test", resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}}}
	connections, err := h.openResolvers(ctx)
	defer func() {
		for _, connection := range connections {
			connection.Close()
		}
		client.Close()
		dialer.wait.Wait()
	}()
	if err != nil || len(connections) != 1 || connections[0] != client || dialer.udp.Load() != 1 {
		t.Fatal("a resolver closing TCP after one reply was selected as a persistent TCP pool", err)
	}
	client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte("carrier")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 7)
	if _, err := io.ReadFull(client, buffer); err != nil || string(buffer) != "carrier" {
		t.Fatal("UDP fallback did not carry traffic", err)
	}
}

func TestTCPDNSParallelRequestsReconnectAndRestoreIDs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	const requests = 32
	var dropped atomic.Bool
	var pending atomic.Int32
	var maximum atomic.Int32
	var gateOnce sync.Once
	gate := make(chan struct{})
	dialer := &tcpProbeDialer{}
	dialer.handle = func(connection net.Conn) {
		wire := &dns.Conn{Conn: connection}
		for {
			query, err := wire.ReadMsg()
			if err != nil {
				return
			}
			if query.Question[0].Qtype == dns.TypeTXT {
				if !dropped.Swap(true) {
					return // A real resolver can close an established connection.
				}
				active := pending.Add(1)
				for previous := maximum.Load(); active > previous; previous = maximum.Load() {
					if maximum.CompareAndSwap(previous, active) {
						break
					}
				}
				if active == tcpDNSProviderWorkers {
					gateOnce.Do(func() { close(gate) })
				}
				select {
				case <-gate:
				case <-ctx.Done():
					return
				}
				pending.Add(-1)
			}
			if wire.WriteMsg(new(dns.Msg).SetReply(query)) != nil {
				return
			}
		}
	}
	h := &Outbound{ctx: ctx, dialer: dialer, tunnelConfig: &tunnelConfig{
		domain: "t.example.test", resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}}}
	connections, err := h.openResolvers(ctx)
	if err != nil || len(connections) != 1 {
		t.Fatal("TCP resolver probe failed", err)
	}
	pool, ok := connections[0].(*tcpDNSPool)
	if !ok || dialer.udp.Load() != 0 {
		t.Fatal("working TCP resolver was replaced with UDP")
	}
	defer func() { pool.Close(); dialer.wait.Wait() }()
	for index := range requests {
		query := new(dns.Msg)
		query.SetQuestion(fmt.Sprintf("q-%d.t.example.test.", index), dns.TypeTXT)
		query.Id = uint16(77 + index)
		packet, _ := query.Pack()
		if _, err := pool.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() {
		seen := make(map[uint16]bool)
		for range requests {
			packet := make([]byte, 4096)
			size, err := pool.Read(packet)
			if err != nil {
				done <- err
				return
			}
			var reply dns.Msg
			if reply.Unpack(packet[:size]) != nil || reply.Id < 77 || reply.Id >= 77+requests || seen[reply.Id] ||
				reply.Question[0].Name != fmt.Sprintf("q-%d.t.example.test.", int(reply.Id)-77) {
				done <- fmt.Errorf("response lost its native request identity")
				return
			}
			seen[reply.Id] = true
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("parallel requests did not complete")
	}
	if maximum.Load() != tcpDNSProviderWorkers || !dropped.Load() {
		t.Fatal("provider connection limit or reconnect was not exercised")
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	query := new(dns.Msg)
	query.SetQuestion("closed.t.example.test.", dns.TypeTXT)
	packet, _ := query.Pack()
	if _, err := pool.Write(packet); err == nil {
		t.Fatal("closed pool accepted a request")
	}
}

func TestTCPDNSRejectsAReplyForAnotherQuestion(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		wire := &dns.Conn{Conn: server}
		query, err := wire.ReadMsg()
		if err != nil {
			return
		}
		reply := new(dns.Msg).SetReply(query)
		reply.Question[0].Name = "another.example.test."
		_ = wire.WriteMsg(reply)
	}()
	query := new(dns.Msg)
	query.SetQuestion("requested.example.test.", dns.TypeTXT)
	packet, _ := query.Pack()
	if _, err := exchangeTCPDNS(client, packet); err == nil {
		t.Fatal("accepted a reply for another question")
	}
}

func TestTCPDNSFullQueueDoesNotBlockOtherResolver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// All TCP workers can be waiting for a slow resolver while its queue fills.
	blocked := &tcpDNSPool{ctx: ctx, cancel: cancel, done: make(chan struct{}), jobs: make(chan []byte, 1)}
	blocked.jobs <- []byte("already queued")
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	remote, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := newLocalAuth()
	if err != nil {
		remote.Close()
		t.Fatal(err)
	}
	relay, err := newDNSRelay([]io.ReadWriteCloser{blocked, remote}, auth)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	child, err := net.DialUDP("udp4", nil, relay.local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	relay.setPeer(child.LocalAddr().(*net.UDPAddr).AddrPort())
	query := new(dns.Msg)
	query.SetQuestion("bulk.t.example.test.", dns.TypeTXT)
	packet, _ := query.Pack()
	for index := range 2 {
		if _, err := child.Write(auth.sealDNS(dnsQuery, uint64(index+1), append([]byte{byte(index)}, packet...))); err != nil {
			t.Fatal(err)
		}
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	size, peer, err := server.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal("a saturated TCP resolver blocked the healthy DNS path:", err)
	}
	var received dns.Msg
	if received.Unpack(buffer[:size]) != nil || received.Question[0].Name != query.Question[0].Name {
		t.Fatal("healthy resolver did not receive the original query")
	}
	reply, _ := new(dns.Msg).SetReply(&received).Pack()
	if _, err := server.WriteToUDP(reply, peer); err != nil {
		t.Fatal(err)
	}
	child.SetReadDeadline(time.Now().Add(time.Second))
	size, err = child.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, valid := auth.openDNS(dnsReply, buffer[:size])
	if !valid || len(payload) < 2 || payload[0] != 1 {
		t.Fatal("healthy path reply lost its authenticated path identity")
	}
}

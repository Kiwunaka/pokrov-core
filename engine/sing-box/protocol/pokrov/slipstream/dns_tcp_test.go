package slipstream

import (
	"context"
	"fmt"
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
	handle func(net.Conn)
	wait   sync.WaitGroup
	udp    atomic.Int32
}

func (d *tcpProbeDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		d.udp.Add(1)
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

func TestTCPDNSParallelRequestsReconnectAndRestoreIDs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	const requests = 16
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
				if active == requests {
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
	if maximum.Load() != requests || !dropped.Load() {
		t.Fatal("parallelism or reconnect was not exercised")
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

package mts

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/mahsanet/dnstt/noise"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type testCarrier struct {
	receive func([]byte)
	peer    *testCarrier
}

func (c *testCarrier) Receive(f func([]byte)) { c.receive = f }
func (c *testCarrier) Send(b []byte) error    { c.peer.receive(append([]byte(nil), b...)); return nil }
func (c *testCarrier) Stop() error            { return nil }
func TestNoiseMuxOverBoardPackets(t *testing.T) {
	key, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) { testNoiseMuxOverBoardPackets(t, key) })
	}
}
func testNoiseMuxOverBoardPackets(t *testing.T, key []byte) {
	a, b := &testCarrier{}, &testCarrier{}
	a.peer = b
	b.peer = a
	client, _ := NewPacketConn(a, false)
	server, _ := NewPacketConn(b, true)
	defer client.Close()
	defer server.Close()
	listener, err := kcp.ServeConn(nil, 0, 0, server)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	ack := make(chan struct{})
	go func() {
		conn, e := listener.AcceptKCP()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		conn.SetStreamMode(true)
		conn.SetMtu(1200)
		sec, e := noise.NewServer(conn, key)
		if e != nil {
			done <- e
			return
		}
		defer sec.Close()
		cfg := smux.DefaultConfig()
		cfg.Version = 2
		m, e := smux.Server(sec, cfg)
		if e != nil {
			done <- e
			return
		}
		defer m.Close()
		stream, e := m.AcceptStream()
		if e != nil {
			done <- e
			return
		}
		defer stream.Close()
		p := make([]byte, 4)
		_, e = io.ReadFull(stream, p)
		if e == nil {
			_, e = stream.Write(p)
		}
		done <- e
		<-ack
	}()
	conn, err := kcp.NewConn2(client.Peer(), nil, 0, 0, client)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetStreamMode(true)
	conn.SetMtu(1200)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	sec, err := noise.NewClient(conn, noise.PubkeyFromPrivkey(key))
	if err != nil {
		t.Fatal(err)
	}
	defer sec.Close()
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	m, err := smux.Client(sec, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s, err := m.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err = io.ReadFull(s, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "test" {
		t.Fatal("wrong response")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	close(ack)
}

type broadcastCarrier struct {
	receive func([]byte)
	peers   *[]*broadcastCarrier
}

func (c *broadcastCarrier) Receive(f func([]byte)) { c.receive = f }
func (c *broadcastCarrier) Send(b []byte) error {
	for _, p := range *c.peers {
		if p != c && p.receive != nil {
			p.receive(append([]byte(nil), b...))
		}
	}
	return nil
}
func (c *broadcastCarrier) Stop() error { return nil }
func TestClientPacketIsolationAndFreshID(t *testing.T) {
	peers := []*broadcastCarrier{}
	newCarrier := func() *broadcastCarrier { c := &broadcastCarrier{peers: &peers}; peers = append(peers, c); return c }
	server, _ := NewPacketConn(newCarrier(), true)
	defer server.Close()
	first, _ := NewPacketConn(newCarrier(), false)
	defer first.Close()
	second, _ := NewPacketConn(newCarrier(), false)
	defer second.Close()
	if first.Peer() == second.Peer() {
		t.Fatal("client IDs collide")
	}
	if _, err := server.WriteTo([]byte("one"), first.Peer()); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-first.incoming:
		if string(p.data) != "one" {
			t.Fatal("wrong packet")
		}
	case <-time.After(time.Second):
		t.Fatal("no packet")
	}
	select {
	case <-second.incoming:
		t.Fatal("packet reached another client")
	default:
	}
	restarted, _ := NewPacketConn(newCarrier(), false)
	defer restarted.Close()
	if restarted.Peer() == first.Peer() {
		t.Fatal("reused client ID")
	}
}

package group

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
)

type youtubeTestPath struct {
	outbound.Adapter
	serve func(net.Conn, M.Socksaddr)
}

func (p *youtubeTestPath) DialContext(_ context.Context, _ string, dest M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	go func() { defer server.Close(); p.serve(server, dest) }()
	return client, nil
}

func (p *youtubeTestPath) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unused TCP fixture")
}

func TestYouTubeStallMovesOnlyNewServiceFlows(t *testing.T) {
	stalled := make(chan struct{})
	first := &youtubeTestPath{serve: func(conn net.Conn, dest M.Socksaddr) {
		if dest.Fqdn != "r.example.googlevideo.com" {
			io.Copy(conn, conn)
			return
		}
		io.Copy(io.Discard, conn)
		close(stalled)
	}}
	second := &youtubeTestPath{serve: func(conn net.Conn, _ M.Socksaddr) { io.Copy(conn, conn) }}
	g := &youtubeOutbound{paths: []adapter.Outbound{first, second}, stall: 40 * time.Millisecond}
	open := func(host string) net.Conn {
		t.Helper()
		c, err := g.DialContext(context.Background(), "tcp", M.Socksaddr{Fqdn: host, Port: 443})
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		t.Cleanup(func() { c.Close() })
		return c
	}
	echo := func(c net.Conn) {
		t.Helper()
		data := make([]byte, 256)
		if _, err := c.Write(data); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, data); err != nil {
			t.Fatal(err)
		}
	}
	ordinary := open("example.org")
	echo(ordinary)
	control := open("www.youtube.com")
	echo(control)
	bad := open("r.example.googlevideo.com")
	if _, err := bad.Write(make([]byte, 256)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stalled:
	case <-time.After(time.Second):
		t.Fatal("stalled flow was not closed")
	}
	if next, _ := g.current(); next != second {
		t.Fatal("media path did not change")
	}
	echo(open("r.example.googlevideo.com"))
	if _, err := control.Read(make([]byte, 1)); err == nil {
		t.Fatal("player retained the previous egress")
	}
	echo(ordinary)
	// Lookalike domains still go through the original path.
	c := open("googlevideo.com.example.org")
	if _, watched := c.(*youtubeConn); watched {
		t.Fatal("unrelated host observed")
	}
}

func TestYouTubeCompletedSmallResponseCanStayIdle(t *testing.T) {
	g := &youtubeOutbound{paths: make([]adapter.Outbound, 2), stall: 20 * time.Millisecond}
	closed := make(chan struct{})
	f := youtubeFlow{owner: g, stopSocket: func() error { close(closed); return nil }}
	f.wrote(256)
	f.read(3000, nil)
	f.wrote(256)
	f.read(1600, nil)
	select {
	case <-closed:
		t.Fatal("paused player was interrupted")
	case <-time.After(3 * g.stall):
	}
	f.close()
	if _, gen := g.current(); gen != 0 {
		t.Fatal("pause changed the media route")
	}
}

func TestYouTubeClassifiesMediaConnectionEnd(t *testing.T) {
	for _, test := range []struct {
		name string
		end  func(*youtubeFlow)
		want uint64
	}{
		{"short response then EOF", func(f *youtubeFlow) { f.read(1600, io.EOF) }, 0},
		{"caller closes after response", func(f *youtubeFlow) { f.read(1600, nil); f.close() }, 0},
		{"EOF without response", func(f *youtubeFlow) { f.read(0, io.EOF) }, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := &youtubeOutbound{paths: make([]adapter.Outbound, 2), stall: time.Minute}
			for range 2 {
				f := youtubeFlow{owner: g}
				f.wrote(256)
				f.read(3000, nil)
				f.wrote(256)
				test.end(&f)
			}
			if _, gen := g.current(); gen != test.want {
				t.Fatalf("egress generation = %d, want %d", gen, test.want)
			}
		})
	}
}

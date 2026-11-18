package group

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type youtubeOptions struct {
	Outbounds []string `json:"outbounds" reference:"outbound"`
}

func RegisterYouTube(registry *outbound.Registry) {
	outbound.Register[youtubeOptions](registry, C.TypePokrovYouTube, newYouTube)
}

// The client supplies the protected routes admitted by the country selection.
// The player's control and media sockets must share the same egress.
type youtubeOutbound struct {
	outbound.Adapter
	manager       adapter.OutboundManager
	flows         *interrupt.Group
	paths         []adapter.Outbound
	mu            sync.Mutex
	generation    uint64
	lastMedia     time.Time
	shortFailures int
	lastCycle     time.Time
	stall         time.Duration
}

func newYouTube(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options youtubeOptions) (adapter.Outbound, error) {
	if len(options.Outbounds) < 2 {
		return nil, errors.New("YouTube needs two protected routes")
	}
	return &youtubeOutbound{Adapter: outbound.NewAdapter(C.TypePokrovYouTube, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		manager: service.FromContext[adapter.OutboundManager](ctx), stall: 12 * time.Second}, nil
}

func (g *youtubeOutbound) Start() error {
	for _, tag := range g.Dependencies() {
		path, ok := g.manager.Outbound(tag)
		if !ok {
			return errors.New("missing YouTube route")
		}
		switch path.Type() {
		case "vless", "hysteria2", "awg", "wireguard":
			g.paths = append(g.paths, path)
		case "naive":
			protected, ok := path.(interface{ IsProtectedH2() bool })
			if !ok || !protected.IsProtectedH2() {
				return errors.New("YouTube requires protected HTTP/2")
			}
			g.paths = append(g.paths, path)
		default:
			return errors.New("unprotected or unsupported YouTube route")
		}
	}
	return nil
}

func (g *youtubeOutbound) current() (adapter.Outbound, uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paths[g.generation%uint64(len(g.paths))], g.generation
}

func (g *youtubeOutbound) healthy(gen uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if gen == g.generation {
		g.lastMedia = time.Now()
		g.shortFailures = 0
	}
}

func (g *youtubeOutbound) failed(gen uint64, since time.Time, definite bool) {
	g.mu.Lock()
	if gen != g.generation || g.lastMedia.After(since) {
		g.mu.Unlock()
		return
	}
	g.shortFailures++
	if !definite && g.shortFailures < 2 {
		g.mu.Unlock()
		return
	}
	now := time.Now()
	if gen%uint64(len(g.paths)) == 0 {
		if now.Sub(g.lastCycle) < time.Minute {
			g.mu.Unlock()
			return
		}
		g.lastCycle = now
	}
	g.generation++
	g.shortFailures = 0
	previous := g.flows
	g.flows = nil
	g.mu.Unlock()
	if previous != nil {
		// Reopen the player API on the same exit as its new media requests.
		// Old signed media URLs may be bound to the previous exit address.
		previous.Interrupt(true)
	}
}

// Register before releasing the generation lock. A dial that finished after
// a switch must never supply an old control connection to the player.
func (g *youtubeOutbound) track(gen uint64, attach func(*interrupt.Group)) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if gen != g.generation {
		return false
	}
	if g.flows == nil {
		g.flows = interrupt.NewGroup()
	}
	attach(g.flows)
	return true
}

func youtubeName(ctx context.Context, dest M.Socksaddr) string {
	name := dest.Fqdn
	if name == "" {
		if m := adapter.ContextFrom(ctx); m != nil {
			name = m.Domain
		}
	}
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func youtubeMedia(name string) bool {
	return name == "googlevideo.com" || strings.HasSuffix(name, ".googlevideo.com")
}

func youtubeService(name string) bool {
	if youtubeMedia(name) {
		return true
	}
	for _, suffix := range []string{"youtube.com", "youtu.be", "ytimg.com", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com"} {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

func (g *youtubeOutbound) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	name := youtubeName(ctx, dest)
	if dest.Port != 443 || !youtubeService(name) {
		return g.paths[0].DialContext(ctx, network, dest)
	}
	path, gen := g.current()
	started := time.Now()
	conn, err := path.DialContext(ctx, network, dest)
	if err != nil && ctx.Err() == nil {
		g.failed(gen, started, true)
		if next, newGen := g.current(); newGen != gen {
			gen = newGen
			conn, err = next.DialContext(ctx, network, dest)
		}
	}
	if err != nil {
		return nil, err
	}
	if !g.track(gen, func(group *interrupt.Group) { conn = group.NewConn(conn, true) }) {
		conn.Close()
		return nil, net.ErrClosed
	}
	if !youtubeMedia(name) {
		return conn, nil
	}
	return &youtubeConn{Conn: conn, flow: youtubeFlow{owner: g, generation: gen, stopSocket: conn.Close}}, nil
}

func (g *youtubeOutbound) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	name := youtubeName(ctx, dest)
	if dest.Port != 443 || !youtubeService(name) {
		return g.paths[0].ListenPacket(ctx, dest)
	}
	path, gen := g.current()
	started := time.Now()
	conn, err := path.ListenPacket(ctx, dest)
	if err != nil && ctx.Err() == nil {
		g.failed(gen, started, true)
		if next, newGen := g.current(); newGen != gen {
			gen = newGen
			conn, err = next.ListenPacket(ctx, dest)
		}
	}
	if err != nil {
		return nil, err
	}
	if !g.track(gen, func(group *interrupt.Group) { conn = group.NewPacketConn(conn, true) }) {
		conn.Close()
		return nil, net.ErrClosed
	}
	if !youtubeMedia(name) {
		return conn, nil
	}
	return &youtubePacket{PacketConn: conn, flow: youtubeFlow{owner: g, generation: gen, stopSocket: conn.Close}}, nil
}

// Observe byte counts only. A completed handshake followed by an idle browser
// does not start a playback deadline.
type youtubeFlow struct {
	mu                                sync.Mutex
	owner                             *youtubeOutbound
	generation                        uint64
	stopSocket                        func() error
	pending                           time.Time
	started, retried, handshake, done bool
	received                          int
	timer                             *time.Timer
}

func (f *youtubeFlow) wrote(n int) {
	if n < 128 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return
	}
	now := time.Now()
	if f.timer != nil {
		if now.Sub(f.pending) >= time.Second {
			f.retried = true
		}
		return
	}
	if !f.started {
		f.started = true
		f.handshake = true
	}
	f.pending = now
	f.received = 0
	f.retried = false
	f.timer = time.AfterFunc(f.owner.stall, func() {
		f.mu.Lock()
		if f.done || f.pending != now {
			f.mu.Unlock()
			return
		}
		if f.received > 0 && !f.retried {
			// A small, completed response followed by silence can be a paused player.
			f.timer = nil
			f.pending = time.Time{}
			f.mu.Unlock()
			return
		}
		f.done = true
		f.mu.Unlock()
		f.owner.failed(f.generation, now, true)
		_ = f.stopSocket()
	})
}

func (f *youtubeFlow) read(n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return
	}
	if n > 0 {
		if f.handshake && f.timer != nil {
			f.timer.Stop()
			f.timer = nil
			f.pending = time.Time{}
			f.handshake = false
		}
		f.received += n
		if f.received >= 32*1024 {
			f.owner.healthy(f.generation)
			f.received = 0
			if f.timer != nil {
				f.timer.Stop()
				f.timer = nil
				f.pending = time.Time{}
			}
		}
	}
	if err != nil {
		f.done = true
		if f.timer != nil {
			f.timer.Stop()
			f.owner.failed(f.generation, f.pending, false)
		}
	}
}

func (f *youtubeFlow) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return
	}
	f.done = true
	if f.timer != nil {
		f.timer.Stop()
		if f.received > 0 {
			f.owner.failed(f.generation, f.pending, false)
		}
	}
}

type youtubeConn struct {
	net.Conn
	flow youtubeFlow
}

func (c *youtubeConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.flow.read(n, e)
	return n, e
}
func (c *youtubeConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.flow.wrote(n)
	return n, e
}
func (c *youtubeConn) Close() error { c.flow.close(); return c.Conn.Close() }

type youtubePacket struct {
	net.PacketConn
	flow youtubeFlow
}

func (c *youtubePacket) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, e := c.PacketConn.ReadFrom(p)
	c.flow.read(n, e)
	return n, a, e
}
func (c *youtubePacket) WriteTo(p []byte, a net.Addr) (int, error) {
	n, e := c.PacketConn.WriteTo(p, a)
	c.flow.wrote(n)
	return n, e
}
func (c *youtubePacket) Close() error { c.flow.close(); return c.PacketConn.Close() }

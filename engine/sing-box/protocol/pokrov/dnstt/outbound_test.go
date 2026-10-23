package dnstt

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mahsanet/dnstt/dns"
	"github.com/mahsanet/dnstt/noise"
	"github.com/mahsanet/dnstt/turbotunnel"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

func TestProtectedVLESSDetourRequiresFixedNoiseGraph(t *testing.T) {
	leaf := option.VLESSOutboundOptions{
		DialerOptions: option.DialerOptions{Detour: "dns-tunnel"},
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 12543},
		UUID:          "00000000-0000-4000-8000-000000000001", Network: "tcp",
	}
	carrier := option.DnsttOptions{Domain: "t.example.test", PublicKey: strings.Repeat("01", 32),
		Resolvers: []string{"192.0.2.1:53"}, Network: "tcp", TunnelPerResolver: 1}
	if !ProtectedVLESSDetour(&leaf, &carrier) {
		t.Fatal("fixed VLESS/Noise graph rejected")
	}
	wrongLeaf := leaf
	wrongLeaf.Server = "192.0.2.2"
	if ProtectedVLESSDetour(&wrongLeaf, &carrier) || ProtectedVLESSDetour(&leaf, nil) {
		t.Fatal("ordinary plaintext VLESS accepted as a Noise detour")
	}
	wrongLeaf = leaf
	wrongLeaf.Network = "udp"
	if ProtectedVLESSDetour(&wrongLeaf, &carrier) {
		t.Fatal("UDP escaped the TCP-only backend")
	}
	wrongCarrier := carrier
	wrongCarrier.PublicKey = "invalid"
	if ProtectedVLESSDetour(&leaf, &wrongCarrier) {
		t.Fatal("unvalidated Noise pin admitted")
	}
	wrongCarrier = carrier
	wrongCarrier.Detour = "direct"
	if ProtectedVLESSDetour(&leaf, &wrongCarrier) {
		t.Fatal("carrier with an alternate detour admitted")
	}
}

type protectedTestNetwork struct {
	adapter.NetworkManager
	protected atomic.Int32
}

func (*protectedTestNetwork) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (*protectedTestNetwork) AutoDetectInterface() bool                { return false }
func (*protectedTestNetwork) DefaultOptions() adapter.NetworkOptions   { return adapter.NetworkOptions{} }
func (*protectedTestNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }
func (n *protectedTestNetwork) ProtectFunc() control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		n.protected.Add(1)
		return nil
	}
}

func newTestOutbound(t *testing.T, resolver, publicKey string, network *protectedTestNetwork) *Outbound {
	t.Helper()
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), network)
	result, err := NewOutbound(ctx, nil, nil, "dns-tunnel", option.DnsttOptions{
		Resolvers: []string{resolver}, Domain: "t.example.test", PublicKey: publicKey,
		Network: "tcp", TunnelPerResolver: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := result.(*Outbound)
	t.Cleanup(func() { h.Close() })
	return h
}

// This uses real loopback UDP, DNSTT TXT framing, KCP, pinned Noise and smux.
// It does not claim an external recursive resolver or production zone works.
func TestDNSTTProtectedWireEchoAndClose(t *testing.T) {
	resolver, publicKey := startDNSTTEcho(t)
	network := &protectedTestNetwork{}
	h := newTestOutbound(t, resolver, publicKey, network)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := h.DialContext(ctx, "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*smux.Stream); !ok {
		t.Fatal("transport retained a payload-logging connection wrapper")
	}
	if h.Type() != C.TypeDNSTT || network.protected.Load() != 1 {
		t.Fatal("DNSTT did not use the protected Core socket dialer")
	}
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	payload := bytes.Repeat([]byte("local tunnel payload\n"), 512)
	written := make(chan error, 1)
	go func() { _, err := conn.Write(payload); written <- err }()
	actual := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, actual); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, payload) {
		t.Fatal("tunnel corrupted bytes")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := h.DialContext(cancelled, "tcp", M.Socksaddr{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled stream request was admitted")
	}
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, actual[:2]); err != nil || string(actual[:2]) != "ok" {
		t.Fatal("cancelled caller killed a healthy shared stream")
	}
	packet := h.session.packet
	closed := make(chan struct{})
	go func() { h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not stop the active tunnel")
	}
	select {
	case <-packet.done:
	default:
		t.Fatal("DNS polling survived Close")
	}
	if _, err := conn.Write([]byte("closed")); err == nil {
		t.Fatal("stream survived outbound Close")
	}
	if _, err := h.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil {
		t.Fatal("closed outbound created a new tunnel")
	}
}

func TestDNSTTBlackholeCancellationAndClose(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	privateKey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	queries := make(chan struct{}, 32)
	go func() {
		var buf [4096]byte
		for {
			if _, _, err := udp.ReadFrom(buf[:]); err != nil {
				return
			}
			queries <- struct{}{}
		}
	}()
	network := &protectedTestNetwork{}
	h := newTestOutbound(t, udp.LocalAddr().String(), noise.EncodeKey(noise.PubkeyFromPrivkey(privateKey)), network)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { _, err := h.DialContext(ctx, "tcp", M.Socksaddr{}); finished <- err }()
	select {
	case <-queries:
	case <-time.After(time.Second):
		t.Fatal("handshake did not reach local DNS resolver")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("handshake lost cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake kept running")
	}
	go func() { _, err := h.DialContext(context.Background(), "tcp", M.Socksaddr{}); finished <- err }()
	select {
	case <-queries:
	case <-time.After(time.Second):
		t.Fatal("second handshake did not start")
	}
	closed := make(chan struct{})
	go func() { h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind a silent peer")
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("handshake succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close leaked setup")
	}
}

func startDNSTTEcho(t *testing.T) (string, string) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	queue := turbotunnel.NewQueuePacketConn(udp.LocalAddr(), 0)
	listener, err := kcp.ServeConn(nil, 0, 0, queue)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); listener.Close(); queue.Close(); udp.Close() })
	go func() {
		conn, err := listener.AcceptKCP()
		if err != nil {
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		conn.SetStreamMode(true)
		conn.SetNoDelay(0, 0, 0, 1)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		conn.SetMtu(1232)
		secure, err := noise.NewServer(conn, privateKey)
		if err != nil {
			return
		}
		defer func() { conn.Close(); io.Copy(io.Discard, secure) }()
		config := smux.DefaultConfig()
		config.Version = 2
		session, err := smux.Server(secure, config)
		if err != nil {
			return
		}
		defer session.Close()
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		io.Copy(stream, stream)
	}()
	// A single-client authoritative endpoint, only for this loopback test.
	// The production server owns client admission and fixed-upstream forwarding.
	go func() {
		var buf [4096]byte
		domain, _ := dns.ParseName("t.example.test")
		for {
			n, peer, err := udp.ReadFrom(buf[:])
			if err != nil {
				return
			}
			query, err := dns.MessageFromWireFormat(buf[:n])
			if err != nil || len(query.Question) != 1 {
				continue
			}
			prefix, ok := query.Question[0].Name.TrimSuffix(domain)
			if !ok {
				continue
			}
			decoded, err := base32Encoding.DecodeString(string(bytes.ToUpper(bytes.Join(prefix, nil))))
			if err != nil || len(decoded) < 8 {
				continue
			}
			var id turbotunnel.ClientID
			copy(id[:], decoded[:8])
			decoded = decoded[8:]
			for len(decoded) > 0 {
				size := int(decoded[0])
				decoded = decoded[1:]
				padding := size >= 224
				if padding {
					size -= 224
				}
				if size > len(decoded) {
					break
				}
				if !padding {
					queue.QueueIncoming(decoded[:size], id)
				}
				decoded = decoded[size:]
			}
			var payload []byte
			select {
			case packet := <-queue.OutgoingQueue(id):
				payload = binary.BigEndian.AppendUint16(payload, uint16(len(packet)))
				payload = append(payload, packet...)
			case <-time.After(10 * time.Millisecond):
			case <-ctx.Done():
				return
			}
			response := dns.Message{
				ID: query.ID, Flags: 0x8400, Question: query.Question,
				Answer: []dns.RR{{Name: query.Question[0].Name, Type: dns.RRTypeTXT, Class: dns.ClassIN, Data: dns.EncodeRDataTXT(payload)}},
			}
			wire, err := response.WireFormat()
			if err == nil {
				udp.WriteTo(wire, peer)
			}
		}
	}()
	return udp.LocalAddr().String(), noise.EncodeKey(noise.PubkeyFromPrivkey(privateKey))
}

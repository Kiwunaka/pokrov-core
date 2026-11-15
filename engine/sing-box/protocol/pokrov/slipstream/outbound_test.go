package slipstream

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func testCertificate(t *testing.T) (certificate, key []byte) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "slipstream.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestSlipstreamRequiresPinnedTCPDetourAndHostExecutable(t *testing.T) {
	certificate, _ := testCertificate(t)
	carrier := option.SlipstreamOptions{Domain: "t.example.test", Certificate: string(certificate),
		Resolvers: []string{"192.0.2.1:53"}, Network: "tcp"}
	leaf := option.VLESSOutboundOptions{
		DialerOptions: option.DialerOptions{Detour: "dns-tunnel"},
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 12543},
		UUID:          "00000000-0000-4000-8000-000000000001", Network: "tcp",
	}
	if !ProtectedVLESSDetour(&leaf, &carrier) {
		t.Fatal("fixed certificate-pinned VLESS graph rejected")
	}
	if _, err := NewOutbound(context.Background(), nil, nil, "dns-tunnel", carrier); err == nil {
		t.Fatal("connection profile selected an unconfigured executable")
	}
	carrier.Certificate = ""
	if ProtectedVLESSDetour(&leaf, &carrier) {
		t.Fatal("missing server pin admitted")
	}
	carrier.Certificate = string(certificate)
	leaf.Network = "udp"
	if ProtectedVLESSDetour(&leaf, &carrier) {
		t.Fatal("UDP admitted to the TCP-only backend")
	}
}

type protectedTestNetwork struct {
	adapter.NetworkManager
	protected  atomic.Int32
	dnsServers []string
}

func (*protectedTestNetwork) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (*protectedTestNetwork) AutoDetectInterface() bool { return false }
func (n *protectedTestNetwork) DefaultNetworkInterface() *adapter.NetworkInterface {
	return &adapter.NetworkInterface{DNSServers: n.dnsServers}
}

func TestResolverPoolUsesCurrentPhysicalDNS(t *testing.T) {
	network := &protectedTestNetwork{dnsServers: []string{"8.8.8.8", "77.88.8.8", "192.0.2.53", "invalid"}}
	h := &Outbound{
		ctx:          service.ContextWith[adapter.NetworkManager](context.Background(), network),
		tunnelConfig: &tunnelConfig{resolvers: []netip.AddrPort{netip.MustParseAddrPort("77.88.8.8:53")}},
	}
	pool := h.resolverPool()
	if len(pool) != 3 || pool[1].String() != "77.88.8.1:53" || pool[2].String() != "192.0.2.53:53" {
		t.Fatal("resolver pool did not preserve allowed public and physical DNS paths")
	}
	network.dnsServers = []string{"192.0.2.54"}
	if pool = h.resolverPool(); len(pool) != 3 || pool[2].String() != "192.0.2.54:53" {
		t.Fatal("resolver pool retained the previous network's DNS")
	}
}

type probeTestDialer struct {
	N.Dialer
	connection net.Conn
}

func (d *probeTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.connection, nil
}

func TestResolverProbeTimeoutRetainsPathButRefusedDoesNot(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(strconv.FormatBool(refused), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				buffer := make([]byte, 4096)
				n, err := server.Read(buffer)
				if err != nil {
					return
				}
				if refused {
					var query dns.Msg
					if query.Unpack(buffer[:n]) != nil {
						return
					}
					reply, _ := new(dns.Msg).SetRcode(&query, dns.RcodeRefused).Pack()
					server.Write(reply)
					return
				}
				io.Copy(server, server)
			}()
			h := &Outbound{ctx: context.Background(),
				tunnelConfig: &tunnelConfig{domain: "t.example.test", resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}},
				dialer:       &probeTestDialer{connection: client}}
			connections, err := h.openResolvers(context.Background())
			if refused {
				if err == nil || len(connections) != 0 {
					t.Fatal("refused resolver was retained")
				}
				return
			}
			if err != nil || len(connections) != 1 {
				t.Fatal("negative A timeout discarded a potentially working TXT path", err)
			}
			connections[0].SetReadDeadline(time.Now().Add(time.Second))
			if _, err := connections[0].Write([]byte("carrier")); err != nil {
				t.Fatal("retained path is not writable", err)
			}
			got := make([]byte, 7)
			if _, err := io.ReadFull(connections[0], got); err != nil || string(got) != "carrier" {
				t.Fatal("retained path is not usable after the probe", err)
			}
		})
	}
}
func (*protectedTestNetwork) DefaultOptions() adapter.NetworkOptions   { return adapter.NetworkOptions{} }
func (*protectedTestNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }
func (n *protectedTestNetwork) ProtectFunc() control.Func {
	return func(string, string, syscall.RawConn) error {
		n.protected.Add(1)
		return nil
	}
}

func testDNSForwarder(t *testing.T, target *net.UDPAddr) *net.UDPConn {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			size, peer, err := front.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buffer[:size]...)
			go func() {
				upstream, err := net.DialUDP("udp4", nil, target)
				if err != nil {
					return
				}
				defer upstream.Close()
				upstream.SetDeadline(time.Now().Add(time.Second))
				if _, err = upstream.Write(packet); err == nil {
					reply := make([]byte, 4096)
					if size, err := upstream.Read(reply); err == nil {
						front.WriteToUDP(reply[:size], peer)
					}
				}
			}()
		}
	}()
	return front
}

// The test uses the patched client and pinned upstream server, real loopback DNS,
// QUIC and leaf pinning. It does not exercise a recursive resolver or TUN host.
func TestSlipstreamProtectedWireEchoAndClose(t *testing.T) {
	directory := os.Getenv("POKROV_SLIPSTREAM_TEST_DIRECTORY")
	if directory == "" {
		t.Skip("set POKROV_SLIPSTREAM_TEST_DIRECTORY to the patched client/pinned server directory")
	}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	certificate, key := testCertificate(t)
	temp := t.TempDir()
	certPath, keyPath := filepath.Join(temp, "server.pem"), filepath.Join(temp, "server.key")
	if os.WriteFile(certPath, certificate, 0o600) != nil || os.WriteFile(keyPath, key, 0o600) != nil {
		t.Fatal("could not write ephemeral server certificate")
	}
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	var backendStreams atomic.Int32
	testUUID := [16]byte{0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1}
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			backendStreams.Add(1)
			go func() {
				defer conn.Close()
				request, err := vless.ReadRequest(conn)
				if err != nil || request.UUID != testUUID || request.Command != 1 || request.Flow != "" {
					return
				}
				// Let the DNS poll finish before the target produces a response.
				// The client must refill that empty poll chain after this request.
				time.Sleep(20 * time.Millisecond)
				if _, err := conn.Write([]byte{vless.Version, 0}); err != nil {
					return
				}
				io.Copy(conn, conn)
			}()
		}
	}()
	reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsPort := reservation.LocalAddr().(*net.UDPAddr).Port
	reservation.Close()
	server := exec.Command(filepath.Join(directory, "slipstream-server"+suffix),
		"--dns-listen-host", "127.0.0.1", "--dns-listen-port", strconv.Itoa(dnsPort),
		"--domain", "t.example.test", "--target-address", backend.Addr().String(),
		"--cert", certPath, "--key", keyPath)
	hideWindow(server)
	if err := server.Start(); err != nil {
		t.Fatal("upstream server could not start:", err)
	}
	t.Cleanup(func() { server.Process.Kill(); server.Wait() })
	time.Sleep(100 * time.Millisecond)
	firstDNS := testDNSForwarder(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dnsPort})
	secondDNS := testDNSForwarder(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dnsPort})
	deadDNS, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deadDNS.Close() })
	network := &protectedTestNetwork{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), network)
	ctx = service.ContextWith[ExecutablePath](ctx, ExecutablePath(filepath.Join(directory, "slipstream-client"+suffix)))
	ctx = filemanager.WithDefault(ctx, temp, temp, os.Getuid(), os.Getgid())
	newTunnel := func(pin []byte) *Outbound {
		t.Helper()
		h, err := NewOutbound(ctx, nil, nil, "dns-tunnel", option.SlipstreamOptions{
			Domain: "t.example.test", Resolvers: []string{deadDNS.LocalAddr().String(), firstDNS.LocalAddr().String(), secondDNS.LocalAddr().String()},
			Certificate: string(pin), Network: "tcp",
		})
		if err != nil {
			t.Fatal(err)
		}
		result := h.(*Outbound)
		t.Cleanup(func() { result.Close() })
		return result
	}
	h := newTunnel(certificate)
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	leaf, err := vless.NewClient("00000000-0000-4000-8000-000000000001", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	dialVLESS := func(tunnel *Outbound) (net.Conn, error) {
		stream, err := tunnel.DialContext(dialCtx, "tcp", M.Socksaddr{})
		if err != nil {
			return nil, err
		}
		conn, err := leaf.DialConn(stream, M.ParseSocksaddr("127.0.0.1:443"))
		if err != nil {
			stream.Close()
		}
		return conn, err
	}
	conn, err := dialVLESS(h)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	// A forged high sequence must not poison the native reply replay window.
	forgedReply := h.session.auth.sealDNS(dnsReply, ^uint64(0)-1, []byte("forged DNS reply"))
	forgedReply[len(forgedReply)-1] ^= 1
	h.session.relay.local.WriteToUDPAddrPort(forgedReply, h.session.relay.peer)
	h.session.relay.local.WriteToUDPAddrPort(h.session.auth.sealDNS(dnsQuery, ^uint64(0)-1, []byte("reflected query")), h.session.relay.peer)
	payload := bytes.Repeat([]byte("slipstream-wire-echo"), 4096)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(payload, reply) {
		t.Fatal("Slipstream QUIC/DNS echo failed:", err)
	}
	if network.protected.Load() != 3 {
		t.Fatal("remote DNS socket did not use the protected dialer")
	}
	before := backendStreams.Load()
	unauthenticated, err := net.DialTimeout("tcp", h.session.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	unauthenticated.SetDeadline(time.Now().Add(2 * time.Second))
	unauthenticated.Write(bytes.Repeat([]byte{0xa5}, 64))
	if _, err := unauthenticated.Read(reply[:1]); err == nil {
		t.Fatal("unauthenticated local peer received application data")
	}
	unauthenticated.Close()
	if backendStreams.Load() != before {
		t.Fatal("unauthenticated local peer opened a remote QUIC stream")
	}
	reflected, err := net.DialTimeout("tcp", h.session.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reflected.SetDeadline(time.Now().Add(2 * time.Second))
	hello := append([]byte(tcpMagic), h.session.auth.generation[:]...)
	hello = append(hello, make([]byte, 32)...)
	reflected.Write(hello)
	var challenge [64]byte
	if _, err := io.ReadFull(reflected, challenge[:]); err != nil {
		t.Fatal("native client did not issue its local challenge:", err)
	}
	reflected.Write(append(challenge[32:], []byte("must-not-open-a-QUIC-stream")...))
	if _, err := reflected.Read(reply[:1]); err == nil {
		t.Fatal("reflected child proof authenticated a foreign parent")
	}
	reflected.Close()
	if backendStreams.Load() != before {
		t.Fatal("foreign parent opened a remote QUIC stream")
	}
	stalled, err := net.DialTimeout("tcp", h.session.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	second, err := dialVLESS(h)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	// A response must not wait for the native client's 400 ms idle keep-alive.
	second.SetDeadline(time.Now().Add(250 * time.Millisecond))
	second.Write(payload[:32])
	if _, err := io.ReadFull(second, reply[:32]); err != nil || !bytes.Equal(payload[:32], reply[:32]) || network.protected.Load() != 3 {
		t.Fatal("concurrent streams did not share the protected client session:", err)
	}
	oldSession := h.session
	firstDNS.Close()
	second.SetDeadline(time.Now().Add(5 * time.Second))
	second.Write(payload[:32])
	if _, err := io.ReadFull(second, reply[:32]); err != nil || !bytes.Equal(payload[:32], reply[:32]) || h.session != oldSession || oldSession.closed() {
		t.Fatal("a failed DNS path stopped the surviving protected session:", err)
	}
	h.InterfaceUpdated(context.Background())
	if !oldSession.closed() {
		t.Fatal("interface reset retained the old native client")
	}
	restarted, err := dialVLESS(h)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.SetDeadline(time.Now().Add(5 * time.Second))
	restarted.Write(payload[:32])
	if _, err := io.ReadFull(restarted, reply[:32]); err != nil || !bytes.Equal(payload[:32], reply[:32]) || network.protected.Load() != 6 {
		t.Fatal("interface reset did not create a fresh protected session:", err)
	}
	stale, err := net.DialTimeout("tcp", h.session.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldSession.auth.authenticate(dialCtx, stale); err == nil {
		t.Fatal("new native generation admitted a previous process key")
	}
	stale.Close()
	session := h.session
	if err := h.Close(); err != nil || !session.closed() {
		t.Fatal("Close left the native client alive")
	}
	restarted.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := restarted.Read(reply[:1]); err == nil {
		t.Fatal("active stream survived transport shutdown")
	}
	if _, err := net.DialTimeout("tcp", session.address, time.Second); err == nil {
		t.Fatal("native listener survived transport shutdown")
	}
	files, err := filepath.Glob(filepath.Join(temp, "slipstream-cert-*.pem"))
	if err != nil || len(files) != 0 {
		t.Fatal("transport retained its temporary certificate file")
	}
	wrongCertificate, _ := testCertificate(t)
	wrong := newTunnel(wrongCertificate)
	bad, err := dialVLESS(wrong)
	if err != nil {
		t.Fatal("wrong-pin client did not reach its local listener:", err)
	}
	defer bad.Close()
	bad.SetDeadline(time.Now().Add(2 * time.Second))
	bad.Write([]byte("must-not-cross-wrong-pin"))
	if _, err := bad.Read(reply[:1]); err == nil {
		t.Fatal("wrong server leaf certificate returned application data")
	}
	wrong.Close()
}

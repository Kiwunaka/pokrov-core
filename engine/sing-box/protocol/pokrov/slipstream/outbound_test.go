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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
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
	protected atomic.Int32
}

func (*protectedTestNetwork) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (*protectedTestNetwork) AutoDetectInterface() bool                { return false }
func (*protectedTestNetwork) DefaultOptions() adapter.NetworkOptions   { return adapter.NetworkOptions{} }
func (*protectedTestNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }
func (n *protectedTestNetwork) ProtectFunc() control.Func {
	return func(string, string, syscall.RawConn) error {
		n.protected.Add(1)
		return nil
	}
}

// The test uses the unmodified upstream client and server, real loopback DNS,
// QUIC and leaf pinning. It does not exercise a recursive resolver or TUN host.
func TestSlipstreamProtectedWireEchoAndClose(t *testing.T) {
	directory := os.Getenv("POKROV_SLIPSTREAM_TEST_DIRECTORY")
	if directory == "" {
		t.Skip("set POKROV_SLIPSTREAM_TEST_DIRECTORY to the upstream client/server directory")
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
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
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
	network := &protectedTestNetwork{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), network)
	ctx = service.ContextWith[ExecutablePath](ctx, ExecutablePath(filepath.Join(directory, "slipstream-client"+suffix)))
	ctx = filemanager.WithDefault(ctx, temp, temp, os.Getuid(), os.Getgid())
	newTunnel := func(pin []byte) *Outbound {
		t.Helper()
		h, err := NewOutbound(ctx, nil, nil, "dns-tunnel", option.SlipstreamOptions{
			Domain: "t.example.test", Resolvers: []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))},
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
	conn, err := h.DialContext(dialCtx, "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	payload := bytes.Repeat([]byte("slipstream-wire-echo"), 4096)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(payload, reply) {
		t.Fatal("Slipstream QUIC/DNS echo failed:", err)
	}
	if network.protected.Load() != 1 {
		t.Fatal("remote DNS socket did not use the protected dialer")
	}
	second, err := h.DialContext(dialCtx, "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetDeadline(time.Now().Add(5 * time.Second))
	second.Write(payload[:32])
	if _, err := io.ReadFull(second, reply[:32]); err != nil || !bytes.Equal(payload[:32], reply[:32]) || network.protected.Load() != 1 {
		t.Fatal("concurrent streams did not share the protected client session:", err)
	}
	oldSession := h.session
	h.InterfaceUpdated(context.Background())
	if !oldSession.closed() {
		t.Fatal("interface reset retained the old native client")
	}
	restarted, err := h.DialContext(dialCtx, "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.SetDeadline(time.Now().Add(5 * time.Second))
	restarted.Write(payload[:32])
	if _, err := io.ReadFull(restarted, reply[:32]); err != nil || !bytes.Equal(payload[:32], reply[:32]) || network.protected.Load() != 2 {
		t.Fatal("interface reset did not create a fresh protected session:", err)
	}
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
	bad, err := wrong.DialContext(dialCtx, "tcp", M.Socksaddr{})
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

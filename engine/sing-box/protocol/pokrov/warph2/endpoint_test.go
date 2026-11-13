package warph2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	wg "github.com/sagernet/sing-box/transport/wireguard"
	M "github.com/sagernet/sing/common/metadata"
)

type localDialer struct{}

func (localDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address.String())
}
func (localDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("HTTP/2 must not open UDP")
}

type packetReceiver chan []byte

type packetSender struct {
	wg.Device
	packet []byte
}

func (p *packetSender) Read(packets [][]byte, sizes []int, _ int) (int, error) {
	if p.packet == nil {
		return 0, io.EOF
	}
	sizes[0] = copy(packets[0], p.packet)
	p.packet = nil
	return 1, nil
}

func (p packetReceiver) Write(packets [][]byte, _ int) (int, error) {
	p <- append([]byte(nil), packets[0]...)
	return len(packets), nil
}

func testTLSConfig(t *testing.T, server *httptest.Server) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(server.Certificate().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &C.WARPConfig{PrivateKey: base64.StdEncoding.EncodeToString(private)}
	if err = json.Unmarshal([]byte(`{"peers":[{}]}`), config); err != nil {
		t.Fatal(err)
	}
	config.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(public)
	result, err := profileTLS(config)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestHTTP2CapsuleTransferAndCancellation(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != http.MethodConnect || r.Header.Get("cf-connect-proto") != "cf-connect-ip" || len(r.TLS.PeerCertificates) == 0 {
			t.Error("CONNECT did not use authenticated HTTP/2")
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		// Cloudflare's HTTP/2 dialect omits the context ID used by HTTP/3.
		frame := make([]byte, 22)
		if _, err := io.ReadFull(r.Body, frame); err != nil {
			t.Error(err)
			return
		}
		if frame[0] != 0 || frame[1] != 20 || frame[2] != 0x45 {
			t.Error("IP datagram did not use Cloudflare's HTTP/2 framing")
			return
		}
		_, _ = w.Write(frame)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()
	address := server.Listener.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Endpoint{ctx: ctx, dialer: localDialer{}, options: option.WireGuardWARPEndpointOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(address.Port)}}}
	current, err := e.connect(testTLSConfig(t, server))
	if err != nil {
		t.Fatal(err)
	}
	defer current.close()
	e.current = current
	packets := make(packetReceiver, 1)
	done := make(chan error, 1)
	go func() { done <- receivePackets(current.reader, packets) }()
	packet := make([]byte, 20)
	packet[0] = 0x45
	go e.sendPackets(&packetSender{packet: packet})
	select {
	case received := <-packets:
		if string(received) != string(packet) {
			t.Fatal("packet changed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/2 did not return the IP packet")
	}
	current.close()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("closed stream did not stop the reader")
		}
	case <-time.After(time.Second):
		t.Fatal("reader remained alive after close")
	}
}

func TestPeerPinRejectsAnotherCertificate(t *testing.T) {
	first := httptest.NewTLSServer(http.NotFoundHandler())
	defer first.Close()
	config := testTLSConfig(t, first)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: &otherKey.PublicKey}}}); err == nil {
		t.Fatal("a different peer key was accepted")
	}
}

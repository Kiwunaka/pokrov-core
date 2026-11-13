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
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/quic-go/quicvarint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
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
		buffer := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buffer)
			if n > 0 {
				_, _ = w.Write(buffer[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
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
	packets := make(packetReceiver, 1)
	done := make(chan error, 1)
	go func() { done <- receivePackets(current.reader, packets) }()
	packet := make([]byte, 20)
	packet[0] = 0x45
	frame := quicvarint.Append(nil, 0)
	frame = quicvarint.Append(frame, uint64(len(packet)))
	frame = append(frame, packet...)
	if _, err = current.writer.Write(frame); err != nil {
		t.Fatal(err)
	}
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

package hysteria2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

func TestUpdateUsersClosesRevokedQUICAndPreservesNeighbor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverTLS, clientTLS := revocationTLS(t)
	server, err := NewService[string](ServiceOptions{Context: ctx, Logger: logger.NOP(), TLSConfig: serverTLS, IgnoreClientBandwidth: true, UDPTimeout: 5 * time.Second, Handler: revocationEchoHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	server.UpdateUsers([]string{"a", "b"}, []string{"synthetic-a", "synthetic-b"})
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(); _ = packetConn.Close() })
	if err := server.Start(packetConn); err != nil {
		t.Fatal(err)
	}
	a := revocationConnect(t, ctx, packetConn.LocalAddr().String(), clientTLS, "synthetic-a")
	b := revocationConnect(t, ctx, packetConn.LocalAddr().String(), clientTLS, "synthetic-b")
	aStream := revocationStream(t, ctx, a)
	bStream := revocationStream(t, ctx, b)
	for _, stream := range []*quic.Stream{aStream, bStream} {
		if err := revocationEcho(stream); err != nil {
			t.Fatal("baseline TCP stream failed", err)
		}
	}
	revocationUDPEcho(t, ctx, a)
	revocationUDPEcho(t, ctx, b)
	// Add another user and reorder the user list. B keeps the same QUIC and
	// stream; a list index must never become its authorization identity.
	server.UpdateUsers([]string{"c", "b", "a"}, []string{"synthetic-c", "synthetic-b", "synthetic-a"})
	if err := revocationEcho(bStream); err != nil {
		t.Fatal("adding a user interrupted the neighboring stream", err)
	}
	c := revocationConnect(t, ctx, packetConn.LocalAddr().String(), clientTLS, "synthetic-c")
	if err := revocationEcho(revocationStream(t, ctx, c)); err != nil {
		t.Fatal("new user could not open a stream", err)
	}
	server.UpdateUsers([]string{"c", "b"}, []string{"synthetic-c", "synthetic-b"})
	select {
	case <-a.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("revoked user's QUIC stayed authenticated")
	}
	if err := revocationEcho(aStream); err == nil {
		t.Fatal("revoked user's existing TCP stream stayed usable")
	}
	if stream, err := a.OpenStreamSync(ctx); err == nil {
		stream.CancelRead(0)
		_ = stream.Close()
		t.Fatal("revoked user's already open QUIC accepted a new stream")
	}
	if err := revocationUDP(ctx, a); err == nil {
		t.Fatal("revoked user's already open QUIC transferred a UDP datagram")
	}
	if err := revocationEcho(bStream); err != nil {
		t.Fatal("revocation interrupted the neighboring TCP stream", err)
	}
	revocationUDPEcho(t, ctx, b)
	if b.Context().Err() != nil {
		t.Fatal("neighbor was forced to reconnect")
	}
	// A fresh QUIC handshake still cannot authenticate with the removed password.
	fresh, err := quic.DialAddr(ctx, packetConn.LocalAddr().String(), clientTLS.Clone(), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.CloseWithError(0, "") })
	if status := revocationAuth(t, ctx, fresh, "synthetic-a"); status == protocol.StatusAuthOK {
		t.Fatal("revoked password authenticated a fresh QUIC")
	}
}

type revocationEchoHandler struct{}

func (revocationEchoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
}

func (revocationEchoHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	for {
		packet := buf.NewPacket()
		destination, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return
		}
		if err := conn.WritePacket(packet, destination); err != nil {
			return
		}
	}
}

func revocationConnect(t *testing.T, ctx context.Context, address string, tlsConfig *tls.Config, password string) *quic.Conn {
	t.Helper()
	conn, err := quic.DialAddr(ctx, address, tlsConfig.Clone(), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	if revocationAuth(t, ctx, conn, password) != protocol.StatusAuthOK {
		t.Fatal("baseline authentication failed")
	}
	return conn
}

func revocationAuth(t *testing.T, ctx context.Context, conn *quic.Conn, password string) int {
	t.Helper()
	transport := &http3.Transport{}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: password})
	response, err := transport.NewClientConn(conn).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response.StatusCode
}

func revocationStream(t *testing.T, ctx context.Context, conn *quic.Conn) *quic.Stream {
	t.Helper()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.CancelRead(0); _ = stream.Close() })
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	request := protocol.WriteTCPRequest("lab.pokrov.test:80", []byte{42})
	defer request.Release()
	if _, err := stream.Write(request.Bytes()); err != nil {
		t.Fatal(err)
	}
	if accepted, _, err := protocol.ReadTCPResponse(stream); err != nil || !accepted {
		t.Fatal("TCP request rejected", err)
	}
	var firstReply [1]byte
	if _, err := io.ReadFull(stream, firstReply[:]); err != nil || firstReply[0] != 42 {
		t.Fatal("initial TCP echo failed", err)
	}
	return stream
}

func revocationEcho(stream *quic.Stream) error {
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	if _, err := stream.Write([]byte{42}); err != nil {
		return err
	}
	var reply [1]byte
	_, err := io.ReadFull(stream, reply[:])
	if err == nil && reply[0] != 42 {
		return errors.New("echo mismatch")
	}
	return err
}

func revocationUDPEcho(t *testing.T, ctx context.Context, conn *quic.Conn) {
	t.Helper()
	if err := revocationUDP(ctx, conn); err != nil {
		t.Fatal(err)
	}
}

func revocationUDP(ctx context.Context, conn *quic.Conn) error {
	message := protocol.UDPMessage{SessionID: 7, FragCount: 1, Addr: "lab.pokrov.test:80", Data: []byte{42}}
	packet := make([]byte, message.Size())
	message.Serialize(packet)
	if err := conn.SendDatagram(packet); err != nil {
		return err
	}
	readCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	reply, err := conn.ReceiveDatagram(readCtx)
	if err != nil {
		return err
	}
	echo, err := protocol.ParseUDPMessage(reply)
	if err != nil || len(echo.Data) != 1 || echo.Data[0] != 42 {
		return errors.New("UDP echo mismatch")
	}
	return nil
}

type revocationTLSConfig struct{ config *tls.Config }

func (c *revocationTLSConfig) ServerName() string                { return c.config.ServerName }
func (c *revocationTLSConfig) SetServerName(v string)            { c.config.ServerName = v }
func (c *revocationTLSConfig) NextProtos() []string              { return c.config.NextProtos }
func (c *revocationTLSConfig) SetNextProtos(v []string)          { c.config.NextProtos = v }
func (c *revocationTLSConfig) HandshakeTimeout() time.Duration   { return 0 }
func (c *revocationTLSConfig) SetHandshakeTimeout(time.Duration) {}
func (c *revocationTLSConfig) STDConfig() (*tls.Config, error)   { return c.config, nil }
func (c *revocationTLSConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return tls.Client(conn, c.config), nil
}
func (c *revocationTLSConfig) Server(conn net.Conn) (aTLS.Conn, error) {
	return tls.Server(conn, c.config), nil
}
func (c *revocationTLSConfig) Clone() aTLS.Config { return &revocationTLSConfig{c.config.Clone()} }
func (c *revocationTLSConfig) Start() error       { return nil }
func (c *revocationTLSConfig) Close() error       { return nil }

func revocationTLS(t *testing.T) (*revocationTLSConfig, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"lab.pokrov.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return &revocationTLSConfig{&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}, &tls.Config{RootCAs: pool, ServerName: "lab.pokrov.test", NextProtos: []string{http3.NextProtoH3}}
}

package box_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/hysteria2"
)

func TestHysteriaReloadKeepsPrivateDNSImmutable(t *testing.T) {
	ctx := context.Background()
	inbounds, outbounds, transports := inbound.NewRegistry(), outbound.NewRegistry(), dns.NewTransportRegistry()
	hysteria2.RegisterInbound(inbounds)
	direct.RegisterInbound(inbounds)
	direct.RegisterOutbound(outbounds)
	local.RegisterTransport(transports)
	ctx = box.Context(ctx, inbounds, outbounds, endpoint.NewRegistry(), transports, service.NewRegistry(), certificate.NewRegistry())
	cert, key, _ := hysteriaLabTLS(t)
	hy2 := map[string]any{"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": 4430,
		"tls": map[string]any{"enabled": true, "certificate": []string{cert}, "key": []string{key}}}
	auxiliary := map[string]any{"type": "direct", "tag": "pokrov-awg-dns", "listen": "10.250.0.1", "listen_port": 53}
	hijack := map[string]any{"inbound": []string{"pokrov-awg-dns"}, "action": "hijack-dns"}
	dnsRule := map[string]any{"inbound": []string{"pokrov-awg-dns"}, "rule_set": []string{"pokrov-ads"}, "action": "predefined", "rcode": "NXDOMAIN"}
	route := map[string]any{"rule_set": []any{map[string]any{"type": "inline", "tag": "pokrov-ads", "rules": []any{map[string]any{"domain_suffix": []string{"ads.pokrov.test"}}}}}}
	document := map[string]any{
		"log":          map[string]any{"disabled": true},
		"experimental": map[string]any{"hysteria_reload": true},
		"inbounds":     []any{hy2, auxiliary},
		"outbounds":    []any{map[string]any{"type": "direct", "tag": "account"}},
		"route":        route,
		"dns": map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}},
			"rules": []any{dnsRule}, "final": "local"},
	}
	setUser := func(name string) {
		hy2["users"] = []any{map[string]any{"name": name, "password": "synthetic-" + name}}
		route["rules"] = []any{hijack, map[string]any{"auth_user": []string{name}, "action": "route", "outbound": "account"}, map[string]any{"action": "reject"}}
	}
	options := func() option.Options {
		data, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		var parsed option.Options
		if err := parsed.UnmarshalJSONContext(ctx, data); err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	setUser("a")
	instance, err := box.New(box.Options{Context: ctx, Options: options()})
	if err != nil {
		t.Fatal(err)
	}
	// Do not start listeners: the private AWG address is not assigned to the test host.
	t.Cleanup(func() { _ = instance.Close() })
	initialDigest := instance.HysteriaRuntimeDigest()
	requireRejected := func(want string) {
		t.Helper()
		err := instance.ReloadHysteria(options())
		if err == nil || err.Error() != want || instance.HysteriaRuntimeDigest() != initialDigest {
			t.Fatalf("invalid reload changed authority: %v", err)
		}
	}
	auxiliary["listen"] = "10.250.0.2"
	requireRejected("hysteria_reload_immutable_change")
	auxiliary["listen"] = "10.250.0.1"
	dnsRule["rcode"] = "REFUSED"
	requireRejected("hysteria_reload_immutable_change")
	dnsRule["rcode"] = "NXDOMAIN"
	delete(hijack, "inbound")
	requireRejected("hysteria_reload_dns_rule_invalid")
	hijack["inbound"] = []string{"pokrov-awg-dns"}
	route["rules"] = append(route["rules"].([]any), map[string]any{"action": "hijack-dns"})
	requireRejected("hysteria_reload_rule_invalid")
	setUser("b")
	next := options()
	if err := instance.ReloadHysteria(next); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(next.RawMessage)
	if instance.HysteriaRuntimeDigest() != hex.EncodeToString(digest[:]) {
		t.Fatal("valid auth reload did not preserve the private DNS configuration")
	}
}

func TestHysteriaReloadClosesOldQUICAndSwapsAccountRoutes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inbounds, outbounds, transports := inbound.NewRegistry(), outbound.NewRegistry(), dns.NewTransportRegistry()
	hysteria2.RegisterInbound(inbounds)
	direct.RegisterOutbound(outbounds)
	transport.RegisterUDP(transports)
	ctx = box.Context(ctx, inbounds, outbounds, endpoint.NewRegistry(), transports, service.NewRegistry(), certificate.NewRegistry())
	cert, key, clientTLS := hysteriaLabTLS(t)
	portSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, port := portSocket.LocalAddr().String(), portSocket.LocalAddr().(*net.UDPAddr).Port
	_ = portSocket.Close()
	inboundConfig := map[string]any{"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": port, "ignore_client_bandwidth": true,
		"tls": map[string]any{"enabled": true, "certificate": []string{cert}, "key": []string{key}}}
	document := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{inboundConfig}, "experimental": map[string]any{"hysteria_reload": true}}
	dnsAddress, dnsEntered, releaseDNS := hysteriaLabDelayedDNS(t, ctx)
	dnsHost, dnsPort, _ := net.SplitHostPort(dnsAddress)
	dnsPortNumber, _ := strconv.Atoi(dnsPort)
	document["dns"] = map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "lab", "server": dnsHost, "server_port": dnsPortNumber}}, "strategy": "ipv4_only"}
	setUsers := func(names []string, rotated bool) {
		var users, accountOutbounds []any
		rules := []any{map[string]string{"action": "resolve", "strategy": "ipv4_only"}}
		for _, name := range names {
			password := "synthetic-" + name
			if rotated && name == "c" {
				password += "-rotated"
			}
			users = append(users, map[string]string{"name": name, "password": password})
			accountOutbounds = append(accountOutbounds, map[string]string{"type": "direct", "tag": "account-" + name})
			rules = append(rules, map[string]any{"auth_user": []string{name}, "action": "route", "outbound": "account-" + name})
		}
		rules = append(rules, map[string]string{"action": "reject"})
		inboundConfig["users"], document["outbounds"] = users, accountOutbounds
		document["route"] = map[string]any{"rules": rules, "default_domain_resolver": "lab"}
	}
	options := func() option.Options {
		data, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		var parsed option.Options
		if err := parsed.UnmarshalJSONContext(ctx, data); err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	setUsers([]string{"a", "b"}, false)
	instance, err := box.New(box.Options{Context: ctx, Options: options()})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	tcpAddress, udpAddress := hysteriaLabEchoServers(t)
	a, b := hysteriaLabConnect(t, ctx, address, clientTLS, "synthetic-a"), hysteriaLabConnect(t, ctx, address, clientTLS, "synthetic-b")
	aStream, bStream := hysteriaLabStream(t, ctx, a, tcpAddress), hysteriaLabStream(t, ctx, b, tcpAddress)
	if err := hysteriaLabUDP(ctx, a, udpAddress); err != nil {
		t.Fatal(err)
	}
	if err := hysteriaLabUDP(ctx, b, udpAddress); err != nil {
		t.Fatal(err)
	}
	initialDigest := instance.HysteriaRuntimeDigest()
	inboundConfig["listen_port"] = port + 1
	if err := instance.ReloadHysteria(options()); err == nil || instance.HysteriaRuntimeDigest() != initialDigest || hysteriaLabEcho(aStream) != nil {
		t.Fatal("immutable listener change modified the running authentication")
	}
	inboundConfig["listen_port"] = port
	setUsers([]string{"c", "b", "a"}, false)
	if err := instance.ReloadHysteria(options()); err != nil || hysteriaLabEcho(bStream) != nil {
		t.Fatalf("adding C interrupted B: %v", err)
	}
	c := hysteriaLabConnect(t, ctx, address, clientTLS, "synthetic-c")
	cStream := hysteriaLabStream(t, ctx, c, tcpAddress)
	_, echoPort, _ := net.SplitHostPort(tcpAddress)
	pendingB := hysteriaLabOpenRequest(t, ctx, b, net.JoinHostPort("blocked.pokrov.test", echoPort))
	_ = pendingB.SetDeadline(time.Now().Add(6 * time.Second))
	select {
	case <-dnsEntered:
	case <-time.After(time.Second):
		t.Fatal("B did not enter delayed DNS matching")
	}
	dnsStarted := time.Now()
	setUsers([]string{"c", "b"}, false)
	next := options()
	if err := instance.ReloadHysteria(next); err != nil {
		t.Fatal(err)
	}
	if time.Since(dnsStarted) > time.Second {
		t.Fatal("unchanged B DNS matching delayed native reload")
	}
	digest := sha256.Sum256(next.RawMessage)
	if instance.HysteriaRuntimeDigest() != hex.EncodeToString(digest[:]) {
		t.Fatal("runtime digest did not describe the applied config")
	}
	if _, exists := instance.Outbound().Outbound("account-a"); exists {
		t.Fatal("revoked account outbound remained loaded")
	}
	hysteriaLabRequireClosed(t, ctx, a, aStream)
	if err := hysteriaLabUDP(ctx, a, udpAddress); err == nil {
		t.Fatal("revoked A transferred a datagram")
	}
	freshA := hysteriaLabDial(t, ctx, address, clientTLS)
	if hysteriaLabAuth(t, ctx, freshA, "synthetic-a") == 233 {
		t.Fatal("revoked A authenticated a fresh QUIC")
	}
	if err := hysteriaLabEcho(bStream); err != nil || b.Context().Err() != nil || hysteriaLabUDP(ctx, b, udpAddress) != nil {
		t.Fatalf("revoke interrupted B's existing TCP/UDP session: %v", err)
	}
	// Keep the real lookup blocked beyond Node's three-second proof bound.
	// The new digest is already loaded while this old rules reader is pending.
	if remaining := 3200*time.Millisecond - time.Since(dnsStarted); remaining > 0 {
		time.Sleep(remaining)
	}
	releaseDNS()
	hysteriaLabReadResponse(t, pendingB)
	if hysteriaLabEcho(pendingB) != nil || hysteriaLabEcho(bStream) != nil {
		t.Fatal("pending B matching did not continue after the rule snapshot swap")
	}
	setUsers([]string{"b", "c"}, true)
	if err := instance.ReloadHysteria(options()); err != nil {
		t.Fatal(err)
	}
	hysteriaLabRequireClosed(t, ctx, c, cStream)
	freshC := hysteriaLabDial(t, ctx, address, clientTLS)
	if hysteriaLabAuth(t, ctx, freshC, "synthetic-c") == 233 {
		t.Fatal("rotated password authenticated a fresh QUIC")
	}
	rotatedC := hysteriaLabConnect(t, ctx, address, clientTLS, "synthetic-c-rotated")
	if hysteriaLabEcho(hysteriaLabStream(t, ctx, rotatedC, tcpAddress)) != nil || hysteriaLabEcho(bStream) != nil || b.Context().Err() != nil {
		t.Fatal("password rotation broke new authority or neighboring B")
	}
}

func hysteriaLabRequireClosed(t *testing.T, ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
	t.Helper()
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("revoked QUIC remained open")
	}
	if hysteriaLabEcho(stream) == nil {
		t.Fatal("revoked existing stream transferred data")
	}
	if next, err := conn.OpenStreamSync(ctx); err == nil {
		next.CancelRead(0)
		_ = next.Close()
		t.Fatal("revoked QUIC opened a new stream")
	}
}

func hysteriaLabDial(t *testing.T, ctx context.Context, address string, config *tls.Config) *quic.Conn {
	t.Helper()
	conn, err := quic.DialAddr(ctx, address, config.Clone(), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return conn
}

func hysteriaLabConnect(t *testing.T, ctx context.Context, address string, config *tls.Config, password string) *quic.Conn {
	t.Helper()
	conn := hysteriaLabDial(t, ctx, address, config)
	if hysteriaLabAuth(t, ctx, conn, password) != 233 {
		t.Fatal("native HY2 authentication failed")
	}
	return conn
}

func hysteriaLabAuth(t *testing.T, ctx context.Context, conn *quic.Conn, password string) int {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, "POST", "https://hysteria/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Hysteria-Auth", password)
	transport := &http3.Transport{}
	response, err := transport.NewClientConn(conn).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response.StatusCode
}

func hysteriaLabStream(t *testing.T, ctx context.Context, conn *quic.Conn, destination string) *quic.Stream {
	stream := hysteriaLabOpenRequest(t, ctx, conn, destination)
	hysteriaLabReadResponse(t, stream)
	return stream
}

func hysteriaLabOpenRequest(t *testing.T, ctx context.Context, conn *quic.Conn, destination string) *quic.Stream {
	t.Helper()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.CancelRead(0); _ = stream.Close() })
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	request := quicvarint.Append(nil, 0x401)
	request = quicvarint.Append(request, uint64(len(destination)))
	request = append(request, destination...)
	request = append(request, 0, 42)
	if _, err := stream.Write(request); err != nil {
		t.Fatal(err)
	}
	return stream
}

func hysteriaLabReadResponse(t *testing.T, stream *quic.Stream) {
	t.Helper()
	var status [1]byte
	if _, err := io.ReadFull(stream, status[:]); err != nil || status[0] != 0 {
		t.Fatal("native TCP route rejected", err)
	}
	reader := quicvarint.NewReader(stream)
	for range 2 {
		size, err := quicvarint.Read(reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(io.Discard, stream, int64(size)); err != nil {
			t.Fatal(err)
		}
	}
	var echo [1]byte
	if _, err := io.ReadFull(stream, echo[:]); err != nil || echo[0] != 42 {
		t.Fatal("native TCP transfer failed", err)
	}
}

func hysteriaLabDelayedDNS(t *testing.T, ctx context.Context) (string, <-chan struct{}, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered, gate := make(chan struct{}, 1), make(chan struct{})
	released := false
	release := func() {
		if !released {
			released = true
			close(gate)
		}
	}
	server := &mDNS.Server{PacketConn: conn, Handler: mDNS.HandlerFunc(func(writer mDNS.ResponseWriter, request *mDNS.Msg) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-gate:
		case <-ctx.Done():
			return
		}
		response := new(mDNS.Msg).SetReply(request)
		for _, question := range request.Question {
			if question.Qtype == mDNS.TypeA {
				response.Answer = append(response.Answer, &mDNS.A{Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 30}, A: net.ParseIP("127.0.0.1")})
			}
		}
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { release(); _ = server.Shutdown(); _ = conn.Close() })
	return conn.LocalAddr().String(), entered, release
}

func hysteriaLabEcho(stream *quic.Stream) error {
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

func hysteriaLabUDP(ctx context.Context, conn *quic.Conn, address string) error {
	packet := []byte{0, 0, 0, 7, 0, 0, 0, 1}
	packet = quicvarint.Append(packet, uint64(len(address)))
	packet = append(packet, address...)
	packet = append(packet, 42)
	if err := conn.SendDatagram(packet); err != nil {
		return err
	}
	readCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	reply, err := conn.ReceiveDatagram(readCtx)
	if err == nil && (len(reply) == 0 || reply[len(reply)-1] != 42) {
		return errors.New("UDP echo mismatch")
	}
	return err
}

func hysteriaLabEchoServers(t *testing.T) (string, string) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	go func() {
		packet := make([]byte, 4096)
		for {
			size, address, err := udp.ReadFrom(packet)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(packet[:size], address)
		}
	}()
	return tcp.Addr().String(), udp.LocalAddr().String()
}

func hysteriaLabTLS(t *testing.T) (string, string, *tls.Config) {
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
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), &tls.Config{RootCAs: pool, ServerName: "lab.pokrov.test", NextProtos: []string{http3.NextProtoH3}}
}

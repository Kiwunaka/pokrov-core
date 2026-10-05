package smartaccess

import (
	"bytes"
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
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type readinessTransport struct {
	adapter.DNSTransport
	tag    string
	url    string
	client *http.Client
}

func (t *readinessTransport) Type() string { return C.DNSTypeHTTPS }
func (t *readinessTransport) Tag() string  { return t.tag }

func (t *readinessTransport) Exchange(ctx context.Context, query *mDNS.Msg) (*mDNS.Msg, error) {
	body, err := query.Pack()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url+"/dns-query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := t.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	answer := new(mDNS.Msg)
	err = answer.Unpack(body)
	return answer, err
}

type readinessTransports struct {
	adapter.DNSTransportManager
	transport adapter.DNSTransport
}

func (m *readinessTransports) Transport(tag string) (adapter.DNSTransport, bool) {
	return m.transport, m.transport != nil && tag == m.transport.Tag()
}

type readinessDNS struct {
	adapter.DNSRouter
	transport adapter.DNSTransport
	calls     int
}

func (r *readinessDNS) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.calls++
	if domain != "service.test" || options.Transport != r.transport || !options.DisableCache ||
		!options.DisableOptimisticCache || options.Strategy != C.DomainStrategyIPv4Only {
		return nil, errScope
	}
	query := new(mDNS.Msg)
	query.SetQuestion(domain+".", mDNS.TypeA)
	response, err := options.Transport.Exchange(ctx, query)
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	for _, record := range response.Answer {
		if address, ok := record.(*mDNS.A); ok {
			addresses = append(addresses, netip.MustParseAddr(address.A.String()))
		}
	}
	return addresses, nil
}

type readinessRoots struct {
	adapter.CertificateStore
	pool *x509.CertPool
}

func (r *readinessRoots) Pool() *x509.CertPool { return r.pool }

// Pipe relay stands in for the public owned address; no socket is opened.
type readinessDialer struct {
	ctx         context.Context
	certificate tls.Certificate
	calls       int
	onHello     func(*tls.ClientHelloInfo)
}

func (d *readinessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP || destination != (M.Socksaddr{Addr: netip.MustParseAddr("1.1.1.1"), Port: 443}) {
		return nil, errScope
	}
	d.calls++
	client, relay := net.Pipe()
	config := &tls.Config{Certificates: []tls.Certificate{d.certificate}, MinVersion: tls.VersionTLS12}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if d.onHello != nil {
			d.onHello(hello)
		}
		return nil, nil
	}
	go func() {
		defer relay.Close()
		server := tls.Server(relay, config)
		if server.HandshakeContext(d.ctx) == nil {
			_, _ = io.Copy(io.Discard, server)
		}
	}()
	return client, nil
}
func (*readinessDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errScope
}

type readinessConnections struct {
	adapter.ConnectionManager
	active atomic.Int32
}

func (m *readinessConnections) NewConnection(ctx context.Context, dialer N.Dialer, incoming net.Conn, metadata adapter.InboundContext, closeFlow N.CloseHandlerFunc) {
	relay, err := dialer.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		N.CloseOnHandshakeFailure(incoming, closeFlow, err)
		return
	}
	m.active.Add(1)
	var copies sync.WaitGroup
	copies.Add(2)
	copyDirection := func(destination, source net.Conn) {
		defer copies.Done()
		_, _ = io.Copy(destination, source)
		_ = incoming.Close()
		_ = relay.Close()
	}
	go copyDirection(relay, incoming)
	go copyDirection(incoming, relay)
	go func() { copies.Wait(); m.active.Add(-1); closeFlow(nil) }()
}

func TestServiceReadinessRequiresOwnedDNSVerifiedTLSAndCurrentScope(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("certificate fixture key unavailable")
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"service.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("certificate fixture unavailable")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("certificate fixture parse failed")
	}
	roots := &readinessRoots{pool: x509.NewCertPool()}
	roots.pool.AddCert(certificate)
	leaseID := "0123456789abcdef0123456789abcdef"
	lease, err := newLeaseAuthorization(leaseID, now.Format(timeLayout), now.Add(2*time.Minute).Format(timeLayout), now.Add(10*time.Minute).Format(timeLayout))
	if err != nil {
		t.Fatal("lease fixture unavailable")
	}
	var dnsAddress atomic.Value
	dnsAddress.Store(netip.MustParseAddr("1.1.1.1"))
	var dnsRequests atomic.Int32
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		query := new(mDNS.Msg)
		if readErr != nil || r.TLS == nil || r.Method != http.MethodPost || r.URL.Path != "/dns-query" ||
			r.Header.Get("Content-Type") != "application/dns-message" || query.Unpack(body) != nil ||
			len(query.Question) != 1 || query.Question[0].Name != "service.test." || query.Question[0].Qtype != mDNS.TypeA {
			http.Error(w, "invalid fixture query", http.StatusBadRequest)
			return
		}
		dnsRequests.Add(1)
		answer := new(mDNS.Msg)
		answer.SetReply(query)
		address := dnsAddress.Load().(netip.Addr)
		answer.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: query.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60}, A: net.IP(address.AsSlice())}}
		body, _ = answer.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer doh.Close()
	transport := &readinessTransport{tag: "pokrov-smart-access-dns-" + leaseID, url: doh.URL, client: doh.Client()}
	transports := &readinessTransports{transport: transport}
	resolver := &readinessDNS{transport: transport}
	connections := &readinessConnections{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, transports)
	ctx = service.ContextWith[adapter.DNSRouter](ctx, resolver)
	ctx = service.ContextWith[adapter.CertificateStore](ctx, roots)
	relay := &readinessDialer{ctx: ctx, certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
	member := &Outbound{Adapter: outbound.NewAdapter(Type, "pokrov-smart-access-"+leaseID, []string{N.NetworkTCP}, nil),
		ctx: ctx, dialer: relay, connection: connections, lease: lease, leases: map[string]*leaseAuthorization{leaseID: lease},
		domains: []option.PokrovSmartAccessDomain{{Name: "service.test", Match: "exact"}},
		relays:  []M.Socksaddr{{Addr: dnsAddress.Load().(netip.Addr), Port: 443}},
		maxNew:  100, maxConcurrent: 2, flows: make(map[*leaseFlow]struct{})}
	defer member.Close()
	group, err := member.ServiceLeaseGroup("ai", []*Outbound{member})
	if err != nil {
		t.Fatal("service group fixture unavailable")
	}
	assertUnavailable := func(message string) {
		t.Helper()
		if delay, err := member.ProbeServiceReadiness(ctx); delay != 0 || err == nil {
			t.Fatal(message)
		}
	}
	assertUnavailable("bare lease supplied readiness without catalog windows")
	active := func() bool { return member.AdmitsNewFlows() }
	closeDNS := group.BindProbeWindow(member, true, transport, active, func(domain string) bool { return domain == "service.test" })
	assertUnavailable("DNS window supplied readiness without TCP window")
	closeRoute := group.BindProbeWindow(member, false, nil, active, func(domain string) bool { return domain == "service.test" })
	if resolver.calls != 0 || relay.calls != 0 {
		t.Fatal("missing scope still performed transport work")
	}
	var visibleSNI atomic.Bool
	relay.onHello = func(hello *tls.ClientHelloInfo) { visibleSNI.Store(hello.ServerName == "service.test") }
	if delay, err := member.ProbeServiceReadiness(ctx); delay == 0 || err != nil || !visibleSNI.Load() ||
		resolver.calls != 1 || dnsRequests.Load() != 1 || relay.calls != 1 || connections.active.Load() != 0 || len(member.flows) != 0 {
		t.Fatal("bound DNS and real verified TLS through NewConnection did not settle")
	}
	if _, err = member.DialContext(ctx, N.NetworkTCP, M.Socksaddr{Fqdn: "service.test", Port: 443}); !errors.Is(err, errScope) {
		t.Fatal("readiness made a raw dialer available")
	}
	dnsAddress.Store(netip.MustParseAddr("8.8.8.8"))
	_, err = member.ProbeServiceReadiness(ctx)
	var probeError *urltest.ProbeError
	if !errors.As(err, &probeError) || probeError.Stage != urltest.ProbeStageDNS || relay.calls != 1 {
		t.Fatal("unowned DNS answer was accepted or reached the relay")
	}
	dnsAddress.Store(member.relays[0].Addr)
	trusted := roots.pool
	roots.pool = x509.NewCertPool()
	_, err = member.ProbeServiceReadiness(ctx)
	if !errors.As(err, &probeError) || probeError.Stage != urltest.ProbeStageTLS {
		t.Fatal("untrusted TLS certificate supplied readiness")
	}
	roots.pool = trusted
	closeRoute()
	assertUnavailable("closed TCP window retained readiness")
	closeRoute = group.BindProbeWindow(member, false, nil, active, func(string) bool { return true })
	relay.onHello = func(*tls.ClientHelloInfo) {
		renewed, renewErr := member.RenewLease(leaseID, "1123456789abcdef0123456789abcdef", now.Format(timeLayout),
			now.Add(3*time.Minute).Format(timeLayout), now.Add(11*time.Minute).Format(timeLayout), func(time.Time) error { return nil })
		if !renewed || renewErr != nil {
			t.Error("lease replacement fixture failed")
		}
	}
	assertUnavailable("old proof confirmed a renewed lease")
	probeCtx, cancelProbe := context.WithCancel(ctx)
	relay.onHello = func(*tls.ClientHelloInfo) { cancelProbe() }
	if delay, err := member.ProbeServiceReadiness(probeCtx); delay != 0 || !errors.Is(err, context.Canceled) || connections.active.Load() != 0 || len(member.flows) != 0 {
		t.Fatal("cancelled handshake supplied readiness or retained its flow")
	}
	closeDNS()
	closeRoute()
}

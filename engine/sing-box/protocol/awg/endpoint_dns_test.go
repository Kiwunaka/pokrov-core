package awg

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type failingDNSRouter struct {
	err         error
	lastOptions adapter.DNSQueryOptions
}

func (r *failingDNSRouter) Start(adapter.StartStage) error { return nil }
func (r *failingDNSRouter) Close() error                   { return nil }
func (r *failingDNSRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	return nil, r.err
}
func (r *failingDNSRouter) ExchangeAsync(ctx context.Context, message *dns.Msg, options adapter.DNSQueryOptions, callback func(*dns.Msg, error)) {
	response, err := r.Exchange(ctx, message, options)
	callback(response, err)
}
func (r *failingDNSRouter) Lookup(_ context.Context, _ string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.lastOptions = options
	return nil, r.err
}
func (*failingDNSRouter) ClearCache()                                    {}
func (*failingDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (*failingDNSRouter) ResetNetwork()                                  {}

type endpointDNSTransport struct{ adapter.DNSTransport }
type endpointDNSTransports struct {
	adapter.DNSTransportManager
	direct, remote adapter.DNSTransport
}

func (m *endpointDNSTransports) Transport(tag string) (adapter.DNSTransport, bool) {
	switch tag {
	case "dns-direct":
		return m.direct, true
	case "dns-remote":
		return m.remote, true
	default:
		return nil, false
	}
}

func TestEndpointResolvesDomainBeforeDialingAWGDevice(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	networkManager, err := route.NewNetworkManager(context.Background(), logger, option.RouteOptions{
		DefaultDomainResolver: &option.DomainResolveOptions{Server: "dns-direct", Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only)},
	}, option.DNSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = networkManager.Close() })
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	transports := &endpointDNSTransports{direct: &endpointDNSTransport{}, remote: &endpointDNSTransport{}}
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, transports)
	for _, test := range []struct {
		name      string
		resolver  *option.DomainResolveOptions
		transport adapter.DNSTransport
	}{
		{"default_bootstrap", nil, transports.direct},
		{"explicit_remote", &option.DomainResolveOptions{Server: "dns-remote", Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only)}, transports.remote},
	} {
		t.Run(test.name, func(t *testing.T) {
			queryOptions, err := defaultDomainDNSQueryOptions(ctx, test.resolver)
			if err != nil {
				t.Fatal(err)
			}
			expected := errors.New("synthetic DNS failure")
			dnsRouter := &failingDNSRouter{err: expected}
			endpoint := &Endpoint{logger: logger, dnsRouter: dnsRouter, dnsQueryOptions: queryOptions}
			destination := M.ParseSocksaddrHostPortStr("probe.example", "443")
			_, err = endpoint.DialContext(ctx, N.NetworkTCP, destination)
			if !errors.Is(err, expected) {
				t.Fatalf("expected AWG endpoint DNS error, got %v", err)
			}
			if dnsRouter.lastOptions.Strategy != C.DomainStrategyIPv4Only || dnsRouter.lastOptions.Transport != test.transport {
				t.Fatal("AWG endpoint ignored its explicit resolver or changed the default bootstrap options")
			}
		})
	}
}

func TestEndpointResolvesDomainBeforeOpeningPacketConnection(t *testing.T) {
	expected := errors.New("synthetic DNS failure")
	dnsRouter := &failingDNSRouter{err: expected}
	endpoint := &Endpoint{
		logger:          log.NewNOPFactory().Logger(),
		dnsRouter:       dnsRouter,
		dnsQueryOptions: adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}
	destination := M.ParseSocksaddrHostPortStr("probe.example", "53")

	_, err := endpoint.ListenPacket(context.Background(), destination)
	if !errors.Is(err, expected) {
		t.Fatalf("expected AWG endpoint DNS error, got %v", err)
	}
	if dnsRouter.lastOptions.Strategy != C.DomainStrategyPreferIPv4 {
		t.Fatal("AWG endpoint ignored the configured default domain resolver options")
	}
}

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
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
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
func (r *failingDNSRouter) Lookup(_ context.Context, _ string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.lastOptions = options
	return nil, r.err
}
func (*failingDNSRouter) ClearCache()                                    {}
func (*failingDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (*failingDNSRouter) ResetNetwork()                                  {}

func TestEndpointResolvesDomainBeforeDialingAWGDevice(t *testing.T) {
	expected := errors.New("synthetic DNS failure")
	dnsRouter := &failingDNSRouter{err: expected}
	endpoint := &Endpoint{
		logger:          log.NewNOPFactory().Logger(),
		dnsRouter:       dnsRouter,
		dnsQueryOptions: adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}
	destination := M.ParseSocksaddrHostPortStr("probe.example", "443")

	_, err := endpoint.DialContext(context.Background(), N.NetworkTCP, destination)
	if !errors.Is(err, expected) {
		t.Fatalf("expected AWG endpoint DNS error, got %v", err)
	}
	if dnsRouter.lastOptions.Strategy != C.DomainStrategyPreferIPv4 {
		t.Fatal("AWG endpoint ignored the configured default domain resolver options")
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

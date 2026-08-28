package awg

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type failingDNSRouter struct {
	err error
}

func (r failingDNSRouter) Start(adapter.StartStage) error { return nil }
func (r failingDNSRouter) Close() error                   { return nil }
func (r failingDNSRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	return nil, r.err
}
func (r failingDNSRouter) Lookup(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return nil, r.err
}
func (failingDNSRouter) ClearCache()                                    {}
func (failingDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (failingDNSRouter) ResetNetwork()                                  {}

func TestEndpointResolvesDomainBeforeDialingAWGDevice(t *testing.T) {
	expected := errors.New("synthetic DNS failure")
	endpoint := &Endpoint{
		logger:    log.NewNOPFactory().Logger(),
		dnsRouter: failingDNSRouter{err: expected},
	}
	destination := M.ParseSocksaddrHostPortStr("probe.example", "443")

	_, err := endpoint.DialContext(context.Background(), N.NetworkTCP, destination)
	if !errors.Is(err, expected) {
		t.Fatalf("expected AWG endpoint DNS error, got %v", err)
	}
}

func TestEndpointResolvesDomainBeforeOpeningPacketConnection(t *testing.T) {
	expected := errors.New("synthetic DNS failure")
	endpoint := &Endpoint{
		logger:    log.NewNOPFactory().Logger(),
		dnsRouter: failingDNSRouter{err: expected},
	}
	destination := M.ParseSocksaddrHostPortStr("probe.example", "53")

	_, err := endpoint.ListenPacket(context.Background(), destination)
	if !errors.Is(err, expected) {
		t.Fatalf("expected AWG endpoint DNS error, got %v", err)
	}
}

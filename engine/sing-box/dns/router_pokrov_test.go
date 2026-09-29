package dns

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

type pokrovFallbackTransport struct {
	TransportAdapter
	failure bool
	calls   atomic.Int32
}

func (t *pokrovFallbackTransport) Start(adapter.StartStage) error { return nil }
func (t *pokrovFallbackTransport) Close() error                   { return nil }
func (t *pokrovFallbackTransport) Reset()                         {}
func (t *pokrovFallbackTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.calls.Add(1)
	if t.failure {
		return nil, errors.New("resolver unavailable")
	}
	response := new(mDNS.Msg)
	response.SetReply(message)
	response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 10).To4()}}
	return response, nil
}
func (t *pokrovFallbackTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(t.Exchange(ctx, message))
}

func TestPokrovDNSFailureFallsThroughAfterUpgrade(t *testing.T) {
	factory, err := log.New(log.Options{Options: option.LogOptions{Disabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer factory.Close()
	failed := &pokrovFallbackTransport{TransportAdapter: NewTransportAdapter("test", "failed", nil), failure: true}
	fallback := &pokrovFallbackTransport{TransportAdapter: NewTransportAdapter("test", "fallback", nil)}
	manager := NewTransportManager(factory.Logger(), nil, nil, "fallback")
	manager.transportByTag = map[string]adapter.DNSTransport{"failed": failed, "fallback": fallback}
	manager.defaultTransport = fallback
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	router, err := NewRouter(ctx, factory, option.DNSOptions{RawDNSOptions: option.RawDNSOptions{DNSClientOptions: option.DNSClientOptions{DisableCache: true}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	rules := []option.DNSRule{
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: []string{"example.com"}}, DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: "failed", BypassIfFailed: true}}}},
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: "fallback"}}}},
	}
	if err = router.Initialize(rules); err != nil {
		t.Fatal(err)
	}
	if err = router.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	response, err := router.Exchange(ctx, message, adapter.DNSQueryOptions{})
	if err != nil || response == nil || len(response.Answer) != 1 {
		t.Fatalf("exchange fallback: response=%v err=%v", response, err)
	}
	addresses, err := router.Lookup(ctx, "example.com", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
	if err != nil || len(addresses) != 1 || addresses[0].String() != "192.0.2.10" {
		t.Fatalf("lookup fallback: addresses=%v err=%v", addresses, err)
	}
	if failed.calls.Load() != 2 || fallback.calls.Load() != 2 {
		t.Fatalf("attempts failed=%d fallback=%d", failed.calls.Load(), fallback.calls.Load())
	}
}

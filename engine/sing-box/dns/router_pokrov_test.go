package dns

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/pokrov/smartaccess"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type pokrovFallbackTransport struct {
	TransportAdapter
	failure         bool
	rcode           int
	calls           atomic.Int32
	onFirstExchange func(context.Context)
}

func (t *pokrovFallbackTransport) Start(adapter.StartStage) error { return nil }
func (t *pokrovFallbackTransport) Close() error                   { return nil }
func (t *pokrovFallbackTransport) Reset()                         {}
func (t *pokrovFallbackTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if t.calls.Add(1) == 1 && t.onFirstExchange != nil {
		t.onFirstExchange(ctx)
	}
	if t.failure {
		return nil, errors.New("resolver unavailable")
	}
	response := new(mDNS.Msg)
	response.SetReply(message)
	if t.rcode != mDNS.RcodeSuccess {
		response.Rcode = t.rcode
		return response, nil
	}
	if message.Question[0].Qtype == mDNS.TypeA {
		response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 10).To4()}}
	}
	return response, nil
}

type pokrovFallbackOutbounds struct {
	adapter.OutboundManager
	member adapter.Outbound
}

func (m *pokrovFallbackOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	return m.member, m.member != nil && m.member.Tag() == tag
}

func TestPokrovSmartDNSDomainWalkKeepsReadinessGuard(t *testing.T) {
	factory, err := log.New(log.Options{Options: option.LogOptions{Disabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer factory.Close()
	leaseID := "0123456789abcdef0123456789abcdef"
	smart := &pokrovFallbackTransport{TransportAdapter: NewTransportAdapter(C.DNSTypeHTTPS, "pokrov-smart-access-dns-"+leaseID, nil)}
	manager := NewTransportManager(factory.Logger(), nil, nil, smart.Tag())
	manager.transportByTag = map[string]adapter.DNSTransport{smart.Tag(): smart}
	manager.defaultTransport = smart
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.ConnectionManager](ctx, &struct{ adapter.ConnectionManager }{})
	outbounds := &pokrovFallbackOutbounds{}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, outbounds)
	router, err := NewRouter(ctx, factory, option.DNSOptions{RawDNSOptions: option.RawDNSOptions{DNSClientOptions: option.DNSClientOptions{DisableCache: true}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	ctx = service.ContextWith[adapter.DNSRouter](ctx, router)
	now := time.Now().UTC().Truncate(time.Second)
	domains := []string{"first.service.test", "second.service.test"}
	rawMember, err := smartaccess.NewOutbound(ctx, nil, factory.Logger(), "pokrov-smart-access-"+leaseID, option.PokrovSmartAccessOutboundOptions{
		LeaseID: leaseID, IssuedAt: now.Format(time.RFC3339), NewFlowsUntil: now.Add(time.Minute).Format(time.RFC3339),
		ActiveFlowsUntil: now.Add(2 * time.Minute).Format(time.RFC3339), RelayAddresses: []string{"1.1.1.1"},
		Domains:                    []option.PokrovSmartAccessDomain{{Name: domains[0], Match: "exact"}, {Name: domains[1], Match: "exact"}},
		MaxNewConnectionsPerMinute: 10, MaxConcurrentConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	member := rawMember.(*smartaccess.Outbound)
	outbounds.member = member
	defer member.Close()
	window := &option.PokrovCatalogWindow{IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
		ServiceID: "service", LeaseID: leaseID, LeaseGroup: []string{leaseID}}
	var gateways []*R.DefaultRule
	var dnsRules []option.DNSRule
	for _, domain := range domains {
		gateway, err := R.NewDefaultRule(ctx, factory.Logger(), option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{Domain: []string{domain}, Network: []string{"tcp"}, IPVersion: 4, Port: []uint16{443}, PokrovCatalogWindow: window},
			RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: member.Tag()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = gateway.Start(); err != nil {
			t.Fatal(err)
		}
		defer gateway.Close()
		gateways = append(gateways, gateway)
		dnsRules = append(dnsRules,
			option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: []string{domain}, QueryType: []option.DNSQueryType{
					option.DNSQueryType(mDNS.TypeA), option.DNSQueryType(mDNS.TypeAAAA), option.DNSQueryType(mDNS.TypeHTTPS), option.DNSQueryType(mDNS.TypeSVCB)}, PokrovCatalogWindow: window},
				DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: smart.Tag()}}}},
			option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: []string{domain}},
				DNSRuleAction:     option.DNSRuleAction{Action: C.RuleActionTypeReject, RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault}}}})
	}
	if err = router.Initialize(dnsRules); err != nil {
		t.Fatal(err)
	}
	if err = router.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	// Hold a real probe at its resolver call, after its member and compiled
	// windows are captured. No TLS connection or successful receipt is fabricated.
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	smart.onFirstExchange = func(ctx context.Context) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	go func() { _, _ = member.ProbeServiceReadiness(probeCtx); close(done) }()
	defer func() { close(release); <-done }()
	select {
	case <-entered:
	case <-done:
		t.Fatal("probe did not reach the scoped resolver")
	}
	assertOpen := func(step string) {
		t.Helper()
		receipt := member.ReadServiceLeaseSelection().Readiness
		if receipt == nil || receipt.Status != "pending" || receipt.FallbackGuardClosed {
			t.Errorf("%s closed readiness for an allowed domain", step)
		}
	}
	assertOpen("internal probe window walk")
	for _, queryType := range []uint16{mDNS.TypeA, mDNS.TypeAAAA, mDNS.TypeHTTPS, mDNS.TypeSVCB} {
		message := new(mDNS.Msg)
		message.SetQuestion(domains[1]+".", queryType)
		calls := smart.calls.Load()
		response, err := router.Exchange(ctx, message, adapter.DNSQueryOptions{})
		if err != nil || response == nil || response.Rcode != mDNS.RcodeSuccess || smart.calls.Load() != calls+1 {
			t.Errorf("query %s did not reach owned DNS", mDNS.TypeToString[queryType])
		} else if queryType != mDNS.TypeA && len(response.Answer) != 0 {
			t.Errorf("query %s did not preserve NOERROR/NODATA", mDNS.TypeToString[queryType])
		}
		assertOpen("DNS " + mDNS.TypeToString[queryType])
	}
	metadata := adapter.InboundContext{Domain: domains[1], Network: "tcp", IPVersion: 4, Destination: M.Socksaddr{Fqdn: domains[1], Port: 443}}
	if gateways[0].Match(&metadata) || !gateways[1].Match(&metadata) {
		t.Fatal("second domain did not select its gateway rule")
	}
	assertOpen("TCP rule walk")
	metadata.Network = "udp"
	metadata.ResetRuleCache()
	if gateways[1].Match(&metadata) {
		t.Fatal("UDP acquired TCP lease authority")
	}
	if receipt := member.ReadServiceLeaseSelection().Readiness; !receipt.FallbackGuardClosed || receipt.Status != "failure" {
		t.Fatal("actual scoped rule bypass did not close readiness")
	}
}

func TestPokrovSmartDNSRefusalRetiresDNSAndTLSSelection(t *testing.T) {
	for _, api := range []string{"exchange", "lookup"} {
		t.Run(api, func(t *testing.T) {
			factory, err := log.New(log.Options{Options: option.LogOptions{Disabled: true}})
			if err != nil {
				t.Fatal(err)
			}
			defer factory.Close()
			leaseID := "0123456789abcdef0123456789abcdef"
			smart := &pokrovFallbackTransport{TransportAdapter: NewTransportAdapter(C.DNSTypeHTTPS, "pokrov-smart-access-dns-"+leaseID, nil)}
			vpn := &pokrovFallbackTransport{TransportAdapter: NewTransportAdapter("test", "vpn-dns", nil)}
			manager := NewTransportManager(factory.Logger(), nil, nil, vpn.Tag())
			manager.transportByTag = map[string]adapter.DNSTransport{smart.Tag(): smart, vpn.Tag(): vpn}
			manager.defaultTransport = vpn
			ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
			ctx = service.ContextWith[adapter.ConnectionManager](ctx, &struct{ adapter.ConnectionManager }{})
			outbounds := &pokrovFallbackOutbounds{}
			ctx = service.ContextWith[adapter.OutboundManager](ctx, outbounds)
			now := time.Now().UTC().Truncate(time.Second)
			member, err := smartaccess.NewOutbound(ctx, nil, factory.Logger(), "pokrov-smart-access-"+leaseID, option.PokrovSmartAccessOutboundOptions{
				LeaseID: leaseID, IssuedAt: now.Format(time.RFC3339), NewFlowsUntil: now.Add(time.Minute).Format(time.RFC3339),
				ActiveFlowsUntil: now.Add(2 * time.Minute).Format(time.RFC3339), RelayAddresses: []string{"1.1.1.1"},
				Domains:                    []option.PokrovSmartAccessDomain{{Name: "service.test", Match: "exact"}},
				MaxNewConnectionsPerMinute: 10, MaxConcurrentConnections: 2,
			})
			if err != nil {
				t.Fatal(err)
			}
			outbounds.member = member
			defer member.(*smartaccess.Outbound).Close()
			window := &option.PokrovCatalogWindow{IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
				ServiceID: "service", LeaseID: leaseID, LeaseGroup: []string{leaseID}}
			gateway, err := R.NewDefaultRule(ctx, factory.Logger(), option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{Domain: []string{"service.test"}, PokrovCatalogWindow: window},
				RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: member.Tag()}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = gateway.Start(); err != nil {
				t.Fatal(err)
			}
			defer gateway.Close()
			router, err := NewRouter(ctx, factory, option.DNSOptions{RawDNSOptions: option.RawDNSOptions{DNSClientOptions: option.DNSClientOptions{DisableCache: true}}})
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			if err = router.Initialize([]option.DNSRule{
				{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: []string{"service.test"}, PokrovCatalogWindow: window},
					DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: smart.Tag(), BypassIfFailed: true}}}},
				{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: vpn.Tag()}}}},
			}); err != nil {
				t.Fatal(err)
			}
			if err = router.Start(adapter.StartStateStart); err != nil {
				t.Fatal(err)
			}
			query := func() bool {
				t.Helper()
				if api == "lookup" {
					addresses, err := router.Lookup(ctx, "service.test", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
					return err == nil && len(addresses) == 1 && addresses[0].String() == "192.0.2.10"
				}
				message := new(mDNS.Msg)
				message.SetQuestion("service.test.", mDNS.TypeA)
				response, err := router.Exchange(ctx, message, adapter.DNSQueryOptions{})
				return err == nil && response != nil && response.Rcode == mDNS.RcodeSuccess && len(response.Answer) == 1
			}
			matchesGateway := func() bool {
				return gateway.Match(&adapter.InboundContext{Domain: "service.test", Network: "tcp"})
			}
			smart.rcode = mDNS.RcodeNameError
			query()
			if !matchesGateway() {
				t.Fatal("NXDOMAIN retired the service provider")
			}
			smart.rcode = mDNS.RcodeRefused
			if !query() || matchesGateway() {
				t.Fatal("REFUSED did not select VPN DNS and retire the matching TLS relay")
			}
			assertDNSFailure := func() {
				t.Helper()
				delay, probeErr := member.(*smartaccess.Outbound).ProbeServiceReadiness(ctx)
				var failure *urltest.ProbeError
				if delay != 0 || !errors.As(probeErr, &failure) || failure.Stage != urltest.ProbeStageDNS {
					t.Fatal("actual DNS refusal became generic unavailable before host VPN recovery")
				}
			}
			assertDNSFailure()
			if ok, err := member.(*smartaccess.Outbound).RenewLease(leaseID, "1123456789abcdef0123456789abcdef", now.Format(time.RFC3339),
				now.Add(2*time.Minute).Format(time.RFC3339), now.Add(3*time.Minute).Format(time.RFC3339), func(time.Time) error { return nil }); !ok || err != nil {
				t.Fatal("same-provider grant renewal fixture failed")
			}
			assertDNSFailure()
			smartCalls := smart.calls.Load()
			if !query() || smart.calls.Load() != smartCalls {
				t.Fatal("subsequent DNS retried the refused service provider")
			}
		})
	}
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

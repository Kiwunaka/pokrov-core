package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type reverseMappingTestDNS struct {
	dns.TransportAdapter
	adapter.Lifecycle
	addr netip.Addr
	ttl  uint32
}

func (s *reverseMappingTestDNS) Reset() {}

func (s *reverseMappingTestDNS) Exchange(_ context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
	return dns.FixedResponse(msg.Id, msg.Question[0], []netip.Addr{s.addr}, s.ttl), nil
}

func (s *reverseMappingTestDNS) ExchangeAsync(ctx context.Context, msg *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(s.Exchange(ctx, msg))
}

type reverseMappingTestOutbound struct {
	outbound.Adapter
	N.Dialer
	failure error
}

func (s *reverseMappingTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, s.failure
}

type reverseMappingTestOutbounds struct {
	adapter.OutboundManager
	byTag map[string]adapter.Outbound
}

func (s reverseMappingTestOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	member, ok := s.byTag[tag]
	return member, ok
}

func (s reverseMappingTestOutbounds) Default() adapter.Outbound { return s.byTag["direct"] }

func TestShortDNSAnswerKeepsVPNRouteAfterUDPFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		factory, err := log.New(log.Options{Options: option.LogOptions{Disabled: true}})
		if err != nil {
			t.Fatal(err)
		}
		defer factory.Close()
		vpnFailure := errors.New("VPN transport failed")
		directDial := errors.New("default Direct dial")
		explicitDirectDial := errors.New("explicit Direct dial")
		newOutbound := func(kind, tag string, failure error) adapter.Outbound {
			return &reverseMappingTestOutbound{Adapter: outbound.NewAdapter(kind, tag, []string{N.NetworkUDP}, nil), failure: failure}
		}
		outbounds := reverseMappingTestOutbounds{byTag: map[string]adapter.Outbound{
			"vpn":          newOutbound(C.TypeVLESS, "vpn", vpnFailure),
			"direct":       newOutbound(C.TypeDirect, "direct", directDial),
			"local-direct": newOutbound(C.TypeDirect, "local-direct", explicitDirectDial),
		}}
		ctx := service.ContextWith[adapter.DNSTransportManager](t.Context(), dns.NewTransportManager(factory.Logger(), nil, outbounds, ""))
		ctx = service.ContextWith[adapter.OutboundManager](ctx, outbounds)
		ctx = service.ContextWith[adapter.ConnectionManager](ctx, NewConnectionManager(factory.Logger()))
		dnsOptions := option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
			ReverseMapping:   true,
			DNSClientOptions: option.DNSClientOptions{DisableExpire: true},
		}}
		dnsRouter, err := dns.NewRouter(ctx, factory, dnsOptions)
		if err != nil {
			t.Fatal(err)
		}
		defer dnsRouter.Close()
		if err := dnsRouter.Start(adapter.StartStateStart); err != nil {
			t.Fatal(err)
		}
		ctx = service.ContextWith[adapter.DNSRouter](ctx, dnsRouter)
		domainRoute := func(domain, tag string) option.Rule {
			return option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{Domain: []string{domain}},
				RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: tag}},
			}}
		}
		rules := []option.Rule{domainRoute("vpn.example", "vpn"), domainRoute("direct.example", "local-direct")}
		router := NewRouter(ctx, factory, option.RouteOptions{Rules: rules}, dnsOptions)
		defer router.Close()
		if err := router.Initialize(rules, nil); err != nil {
			t.Fatal(err)
		}
		addr := netip.MustParseAddr("192.0.2.10")
		exchange := func(tag string, ttl uint32) {
			t.Helper()
			transport := &reverseMappingTestDNS{TransportAdapter: dns.NewTransportAdapter(C.DNSTypeUDP, tag, nil), addr: addr, ttl: ttl}
			msg := new(mDNS.Msg).SetQuestion("vpn.example.", mDNS.TypeA)
			reply, err := dnsRouter.Exchange(ctx, msg, adapter.DNSQueryOptions{Transport: transport})
			if err != nil || reply == nil || len(reply.Answer) != 1 || reply.Answer[0].Header().Ttl != ttl {
				t.Fatalf("%s did not answer with TTL %d: %v, %v", tag, ttl, reply, err)
			}
		}
		metadata := adapter.InboundContext{
			Source:      M.SocksaddrFrom(netip.MustParseAddr("192.0.2.20"), 12345),
			Destination: M.SocksaddrFrom(addr, 443),
		}
		tryFlow := func(flow adapter.InboundContext, want error) {
			t.Helper()
			conn, peer := net.Pipe()
			defer peer.Close()
			defer conn.Close()
			var failure error
			router.RoutePacketConnectionEx(ctx, bufio.NewUnbindPacketConn(conn), flow, func(err error) { failure = err })
			if !errors.Is(failure, want) {
				t.Fatalf("UDP flow: got %v, want %v", failure, want)
			}
		}

		exchange("long", 300)
		tryFlow(metadata, vpnFailure)
		exchange("short", 1)
		time.Sleep(2 * time.Second)
		tryFlow(metadata, vpnFailure)
		// A known name still selects its explicit Direct rule.
		direct := metadata
		direct.Domain = "direct.example"
		tryFlow(direct, explicitDirectDial)
		time.Sleep(299 * time.Second)
		if _, ok := dnsRouter.LookupReverseMapping(addr); ok {
			t.Fatal("reverse mapping survived both DNS answers")
		}
	})
}

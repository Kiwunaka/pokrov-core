//go:build with_clash_api

package daemon

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/pokrov/localdpi"
	"github.com/sagernet/sing-box/protocol/pokrov/telegramws"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/service"
)

func TestTelegramWSRevokeKeepsOtherHolderAndVPN(t *testing.T) {
	registry := outbound.NewRegistry()
	telegramws.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	ctx := service.ContextWith[adapter.OutboundRegistry](context.Background(), registry)
	ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, registry)
	s := NewStartedService(ServiceOptions{Context: ctx, LogMaxLines: 1})
	t.Cleanup(func() { _ = s.Close() })
	options := option.Options{Log: &option.LogOptions{Disabled: true}, Outbounds: []option.Outbound{{Type: C.TypeVLESS, Tag: "vpn", Options: &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1}, UUID: "00000000-0000-0000-0000-000000000001",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
	}}}, Route: &option.RouteOptions{Final: "vpn"}}
	graph, err := telegramws.FallbackDefinitions(options, "vpn")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, name := range []string{"a", "b"} {
		tg := &option.PokrovTelegramWSOutboundOptions{VPNOutbound: "vpn", ServiceID: "service-" + name,
			IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
			Datacenters: []option.PokrovTelegramWSDatacenter{{ID: 2, Addresses: []string{"149.154.167.50"}, WebsocketAddress: "149.154.167.220"}}}
		tg.NativePreparationID, err = telegramws.RegisterPreparation(*tg, graph)
		if err != nil {
			t.Fatal(err)
		}
		options.Outbounds = append(options.Outbounds, option.Outbound{Type: telegramws.Type, Tag: "pokrov-telegram-ws-service-" + name, Options: tg})
	}
	instance, err := s.newInstanceOptions(options, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.instance, s.serviceStatus.Status = instance, ServiceStatus_STARTED
	var holders []*telegramws.Outbound
	for _, tag := range []string{"pokrov-telegram-ws-service-a", "pokrov-telegram-ws-service-b"} {
		raw, _ := instance.instance.Outbound().Outbound(tag)
		h := raw.(*telegramws.Outbound)
		// Start only these holders; no Box.Start, listeners, TUN or network dial.
		if err := h.Start(); err != nil {
			t.Fatal(err)
		}
		id, err := s.ReadTelegramWSAdmissionID(tag)
		if err != nil || id == "" || h.IsReady() {
			t.Fatal("TG holder did not start unavailable")
		}
		if ok, err := s.AdmitTelegramWSAdmission(id); err != nil || !ok {
			t.Fatal("fresh TG ID was not admitted")
		}
		holders = append(holders, h)
	}
	vpn, _ := instance.instance.Outbound().Outbound("vpn")
	if ok, err := s.RevokeRoutingCatalogService("service-a"); err != nil || !ok || holders[0].IsReady() || !holders[1].IsReady() {
		t.Fatal("TG revoke changed another service")
	}
	if ok, err := s.AdmitTelegramWSAdmission(holders[0].AdmissionID()); err != nil || ok {
		t.Fatal("revoked TG reopened")
	}
	if ok, err := s.WithdrawTelegramWSAdmission("stale-id"); err != nil || ok || !holders[1].IsReady() {
		t.Fatal("stale TG ID changed a current holder")
	}
	if current, _ := instance.instance.Outbound().Outbound("vpn"); current != vpn {
		t.Fatal("TG revoke changed ordinary VPN")
	}
	if ok, err := s.RevokeRoutingCatalog(); err != nil || !ok || holders[1].IsReady() {
		t.Fatal("whole-catalog revoke left TG authority live")
	}
}

func localDpiCatalogFixture(t *testing.T) (*StartedService, option.Options) {
	t.Helper()
	registry := outbound.NewRegistry()
	localdpi.RegisterOutbound(registry)
	socks.RegisterOutbound(registry)
	ctx := service.ContextWith[adapter.OutboundRegistry](context.Background(), registry)
	ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, registry)
	s := NewStartedService(ServiceOptions{Context: ctx, LogMaxLines: 1})
	t.Cleanup(func() { _ = s.Close() })
	options := option.Options{
		Log: &option.LogOptions{Disabled: true},
		Outbounds: []option.Outbound{{
			Type: C.TypeSOCKS, Tag: "vpn",
			Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1}},
		}},
		Route: &option.RouteOptions{Final: "vpn"},
	}
	now := time.Now().UTC()
	for _, name := range []string{"a", "b"} {
		options.Outbounds = append(options.Outbounds, option.Outbound{
			Type: localdpi.Type, Tag: "local-" + name,
			Options: &option.PokrovLocalDPIOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1},
				ServiceID:     "service-" + name, VPNOutbound: "vpn",
			},
		})
		options.Route.Rules = append(options.Route.Rules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Domain: []string{"catalog-" + name + ".invalid"},
					PokrovCatalogWindow: &option.PokrovCatalogWindow{
						IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339),
						ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), ServiceID: "service-" + name,
					},
				},
				RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "vpn"}},
			},
		})
	}
	// Only construct the runtime: no Start, TUN, local listener, or network dial.
	instance, err := s.newInstanceOptions(options, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.instance = instance
	s.serviceStatus.Status = ServiceStatus_STARTED
	return s, options
}

func localDpiFixtureOutbound(t *testing.T, s *StartedService, tag string) *localdpi.Outbound {
	t.Helper()
	raw, found := s.instance.instance.Outbound().Outbound(tag)
	local, ok := raw.(*localdpi.Outbound)
	if !found || !ok {
		t.Fatal("local DPI holder missing")
	}
	return local
}

func TestLocalDpiWithdrawalPreservesOtherAdmissionAndCatalog(t *testing.T) {
	s, options := localDpiCatalogFixture(t)
	a, b := localDpiFixtureOutbound(t, s, "local-a"), localDpiFixtureOutbound(t, s, "local-b")
	idA, err := s.ReadLocalDpiAdmissionID("local-a")
	if err != nil || idA == "" || idA != a.AdmissionID() || idA == b.AdmissionID() || a.IsReady() || b.IsReady() {
		t.Fatal("holder identity was not fresh and dormant")
	}
	if id, err := s.ReadLocalDpiAdmissionID("vpn"); id != "" || err == nil || err.Error() != "local_dpi_admission_unavailable" {
		t.Fatal("non-local outbound supplied admission identity")
	}
	encoded, err := s.ReadLocalDpiObservation(idA)
	var observation localdpi.Observation
	if err != nil || json.Unmarshal([]byte(encoded), &observation) != nil || observation != (localdpi.Observation{State: "unpublished"}) {
		t.Fatal("fresh holder observation unavailable")
	}
	for _, id := range []string{idA, b.AdmissionID()} {
		if admitted, err := s.AdmitLocalDpiAdmission(id); err != nil || !admitted {
			t.Fatal("captured holder was not admitted")
		}
	}
	vpn, _ := s.instance.instance.Outbound().Outbound("vpn")
	if changed, err := s.WithdrawLocalDpiAdmission(idA); err != nil || !changed || a.IsReady() || !b.IsReady() {
		t.Fatal("withdrawal was not scoped to A")
	}
	if admitted, err := s.AdmitLocalDpiAdmission(idA); err != nil || admitted {
		t.Fatal("withdrawn admission reopened")
	}
	encoded, err = s.ReadLocalDpiObservation(idA)
	if err != nil || json.Unmarshal([]byte(encoded), &observation) != nil || observation != (localdpi.Observation{State: "withdrawn", WithdrawCompleted: true}) {
		t.Fatal("current withdrawn holder observation unavailable")
	}
	if current, found := s.instance.instance.Outbound().Outbound("vpn"); !found || current != vpn {
		t.Fatal("withdrawal changed VPN outbound")
	}
	rules := s.instance.instance.Router().Rules()
	if len(rules) != 2 {
		t.Fatal("catalog windows missing from fixture")
	}
	for i, rule := range rules {
		domain := []string{"catalog-a.invalid", "catalog-b.invalid"}[i]
		if !rule.Match(&adapter.InboundContext{Domain: domain}) {
			t.Fatal("local withdrawal revoked catalog window")
		}
	}
	// Construct the same profile in another current instance. Neither tag nor
	// unchanged profile bytes let the old captured ID observe its successor.
	old := s.instance
	next, err := s.newInstanceOptions(options, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.instance = next
	defer func() { _ = old.Close() }()
	if encoded, err := s.ReadLocalDpiObservation(idA); err != nil || encoded != "" {
		t.Fatal("stale ID observed a same-profile successor")
	}
	nextID, err := s.ReadLocalDpiAdmissionID("local-a")
	if err != nil || nextID == idA {
		t.Fatal("same-profile successor reused its admission ID")
	}
	encoded, err = s.ReadLocalDpiObservation(nextID)
	if err != nil || json.Unmarshal([]byte(encoded), &observation) != nil || observation != (localdpi.Observation{State: "unpublished"}) {
		t.Fatal("successor inherited old holder observation")
	}
	s.serviceStatus.Status = ServiceStatus_IDLE
	if encoded, err := s.ReadLocalDpiObservation(nextID); encoded != "" || err == nil {
		t.Fatal("stopped runtime supplied a holder observation")
	}
}

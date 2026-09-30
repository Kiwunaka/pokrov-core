//go:build with_clash_api

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/pokrov/localdpi"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing/service"
)

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
	s, _ := localDpiCatalogFixture(t)
	a, b := localDpiFixtureOutbound(t, s, "local-a"), localDpiFixtureOutbound(t, s, "local-b")
	idA, err := s.ReadLocalDpiAdmissionID("local-a")
	if err != nil || idA == "" || idA != a.AdmissionID() || idA == b.AdmissionID() || a.IsReady() || b.IsReady() {
		t.Fatal("holder identity was not fresh and dormant")
	}
	if id, err := s.ReadLocalDpiAdmissionID("vpn"); id != "" || err == nil || err.Error() != "local_dpi_admission_unavailable" {
		t.Fatal("non-local outbound supplied admission identity")
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
}

func TestLocalDpiStaleAdmissionCannotWithdrawSameProfileReload(t *testing.T) {
	s, options := localDpiCatalogFixture(t)
	old := s.instance
	oldID, err := s.ReadLocalDpiAdmissionID("local-a")
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.newInstanceOptions(options, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.serviceAccess.Lock()
	s.instance = next
	s.serviceAccess.Unlock()
	_ = old.Close()
	newID, err := s.ReadLocalDpiAdmissionID("local-a")
	if err != nil || newID == "" || newID == oldID {
		t.Fatal("same profile reused old admission identity")
	}
	if admitted, err := s.AdmitLocalDpiAdmission(newID); err != nil || !admitted {
		t.Fatal("new holder was not admitted")
	}
	if changed, err := s.WithdrawLocalDpiAdmission(oldID); err != nil || changed || !localDpiFixtureOutbound(t, s, "local-a").IsReady() {
		t.Fatal("stale withdrawal changed replacement runtime")
	}
	if admitted, err := s.AdmitLocalDpiAdmission(oldID); err != nil || admitted {
		t.Fatal("old proof admitted replacement runtime")
	}
}

func TestLocalDpiAdmissionControlsRejectStoppedRuntime(t *testing.T) {
	s, _ := localDpiCatalogFixture(t)
	id, err := s.ReadLocalDpiAdmissionID("local-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CloseService(); err != nil {
		t.Fatal(err)
	}
	if value, err := s.ReadLocalDpiAdmissionID("local-a"); value != "" || err == nil || err.Error() != "local_dpi_runtime_unavailable" {
		t.Fatal("stopped runtime published admission identity")
	}
	for _, change := range []func(string) (bool, error){s.AdmitLocalDpiAdmission, s.WithdrawLocalDpiAdmission} {
		if changed, err := change(id); changed || err == nil || err.Error() != "local_dpi_runtime_unavailable" {
			t.Fatal("stopped runtime accepted admission change")
		}
	}
}

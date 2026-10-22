package dns

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
)

func catalogTestRule(t *testing.T, serviceID string) adapter.DNSRule {
	t.Helper()
	options := option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: []string{"service.test"}},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeReject,
		},
	}
	if serviceID != "" {
		now := time.Now().UTC().Truncate(time.Second)
		options.PokrovCatalogWindow = &option.PokrovCatalogWindow{
			IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
			ServiceID: serviceID,
		}
	}
	rule, err := R.NewDefaultDNSRule(context.Background(), nil, options, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = rule.Start(); err != nil {
		t.Fatal(err)
	}
	return rule
}

func TestCatalogRevocationPreservesOtherServicesAndManualRules(t *testing.T) {
	first := catalogTestRule(t, "first")
	second := catalogTestRule(t, "second")
	manual := catalogTestRule(t, "")
	router := &Router{rules: []adapter.DNSRule{first, second, manual}}
	defer router.Close()
	matches := func(rule adapter.DNSRule) bool {
		return rule.Match(&adapter.InboundContext{Domain: "service.test"})
	}
	if !matches(first) || !matches(second) || !matches(manual) {
		t.Fatal("initial DNS rules did not match")
	}
	if router.RevokeRoutingCatalogService("missing") || !router.RevokeRoutingCatalogService("first") {
		t.Fatal("service revocation returned an incorrect match result")
	}
	if matches(first) || !matches(second) || !matches(manual) {
		t.Fatal("service revocation affected the wrong DNS rules")
	}
	if !router.RevokeRoutingCatalog() || matches(second) || !matches(manual) {
		t.Fatal("catalog revocation did not preserve manual DNS rules")
	}
}

func TestCatalogRevocationDuringRouterClose(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		name := "catalog"
		if scoped {
			name = "service"
		}
		t.Run(name, func(t *testing.T) {
			router := &Router{rules: []adapter.DNSRule{catalogTestRule(t, "service")}}
			revoke := router.RevokeRoutingCatalog
			if scoped {
				revoke = func() bool { return router.RevokeRoutingCatalogService("service") }
			}
			start := make(chan struct{})
			var done sync.WaitGroup
			done.Add(2)
			go func() {
				defer done.Done()
				<-start
				revoke()
			}()
			go func() {
				defer done.Done()
				<-start
				router.Close()
			}()
			close(start)
			done.Wait()
			if revoke() {
				t.Fatal("closed DNS router retained catalog rules")
			}
		})
	}
}

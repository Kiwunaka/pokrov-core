package group

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

type selectionTestOutbound struct {
	adapter.Outbound
	tag string
}

func (o selectionTestOutbound) Tag() string       { return o.tag }
func (o selectionTestOutbound) Network() []string { return []string{"tcp"} }

func TestURLTestFailureDoesNotReplaceHealthyOutbound(t *testing.T) {
	healthy := selectionTestOutbound{tag: "healthy-path"}
	failed := selectionTestOutbound{tag: "failed-path"}
	history := urltest.NewHistoryStorage()
	group := &URLTestGroup{
		outbounds: []adapter.Outbound{healthy, failed}, history: history, tolerance: 50,
	}
	fallback, live := group.Select("tcp")
	if live || fallback == nil || fallback.Tag() != healthy.Tag() {
		t.Fatal("cold group did not provide its TCP fallback")
	}
	if current := (&URLTest{group: group}).Now(); current != fallback.Tag() {
		t.Fatal("cold current tag did not match the TCP dial fallback")
	}
	if group.selectedOutboundTCP != nil || group.selectedOutboundUDP != nil ||
		history.LoadURLTestHistory(healthy.Tag()) != nil {
		t.Fatal("reading the cold current tag published selection or probe history")
	}
	history.StoreURLTestHistory(healthy.Tag(), &adapter.URLTestHistory{Delay: 100})
	history.DeleteURLTestHistory(failed.Tag())
	group.selectedOutboundTCP = healthy
	assertHealthy := func() {
		t.Helper()
		selected, live := group.Select("tcp")
		if !live || selected == nil || selected.Tag() != healthy.Tag() {
			t.Fatal("failed probe displaced the healthy outbound")
		}
	}
	assertHealthy()
	group.selectedOutboundTCP = failed
	assertHealthy()
}

func TestURLTestPreferredDirectSurvivesFasterBridgeAndRecovers(t *testing.T) {
	direct := selectionTestOutbound{tag: "direct-path"}
	directAlt := selectionTestOutbound{tag: "direct-alternate"}
	bridge := selectionTestOutbound{tag: "bridge-path"}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(direct.Tag(), &adapter.URLTestHistory{Delay: 300})
	history.StoreURLTestHistory(directAlt.Tag(), &adapter.URLTestHistory{Delay: 270})
	history.StoreURLTestHistory(bridge.Tag(), &adapter.URLTestHistory{Delay: 100})
	group := &URLTestGroup{
		outbounds: []adapter.Outbound{bridge, direct, directAlt}, history: history, tolerance: 50,
		selectedOutboundTCP: bridge,
	}
	if selected, live := group.Select("tcp"); !live || selected.Tag() != bridge.Tag() {
		t.Fatal("unannotated group lost its latency selection")
	}
	group.preferredTags = []string{direct.Tag(), directAlt.Tag()}
	assertSelected := func(expected string) {
		t.Helper()
		selected, live := group.Select("tcp")
		if !live || selected == nil || selected.Tag() != expected {
			t.Fatalf("wrong live tier selection, expected %s", expected)
		}
		group.selectedOutboundTCP = selected
	}
	assertSelected(direct.Tag())
	// The slightly faster direct sibling stays within the existing hysteresis.
	assertSelected(direct.Tag())
	history.DeleteURLTestHistory(direct.Tag())
	history.DeleteURLTestHistory(directAlt.Tag())
	assertSelected(bridge.Tag())
	history.StoreURLTestHistory(direct.Tag(), &adapter.URLTestHistory{Delay: 300})
	assertSelected(direct.Tag())
}

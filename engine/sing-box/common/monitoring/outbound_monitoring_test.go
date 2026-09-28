package monitoring

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type testOutbound struct {
	adapter.Outbound
	tag string
}

func (o *testOutbound) Tag() string { return o.tag }

type testGroup struct {
	adapter.OutboundGroup
	tag      string
	selected string
}

func (g *testGroup) Tag() string { return g.tag }
func (g *testGroup) Now() string { return g.selected }

type testOutboundManager struct {
	adapter.OutboundManager
	defaultOutbound adapter.Outbound
	outbounds       map[string]adapter.Outbound
}

func (m *testOutboundManager) Default() adapter.Outbound { return m.defaultOutbound }
func (m *testOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, ok := m.outbounds[tag]
	return outbound, ok
}

func TestMonitoringTargetsOnlySelectedPath(t *testing.T) {
	de := &testOutbound{tag: "de"}
	ch := &testOutbound{tag: "ch"}
	balancer := &testGroup{tag: "balancer", selected: "de"}
	selector := &testGroup{tag: "selector", selected: "balancer"}
	m := &OutboundMonitoring{
		ctx: context.Background(),
		outboundManager: &testOutboundManager{
			defaultOutbound: selector,
			outbounds: map[string]adapter.Outbound{
				"balancer": balancer,
				"de":       de,
				"ch":       ch,
			},
		},
		outbounds: map[string]*outboundState{
			"de": {invalid: true},
			"ch": {invalid: true},
		},
		mainInterval: time.Minute,
	}

	if got := m.collectCycleTargets(); !reflect.DeepEqual(got, []string{"de"}) {
		t.Fatalf("selected DE path: got %v", got)
	}
	balancer.selected = "ch"
	if got := m.collectCycleTargets(); !reflect.DeepEqual(got, []string{"ch"}) {
		t.Fatalf("selected CH path: got %v", got)
	}
	if err := m.TestNow("de"); err == nil {
		t.Fatal("unselected outbound accepted for manual test")
	}
	deState := m.outbounds["de"]
	deState.queued = true
	deState.enqueuedCycle = 1
	resultCh := make(chan testOutcome, 1)
	m.executeTask(&testTask{outboundTag: "de", cycleID: 1, resultCh: resultCh})
	if deState.queued || deState.enqueuedCycle != 0 || (<-resultCh).err == nil {
		t.Fatal("stale test remained queued after selection changed")
	}
	balancer.selected = ""
	if got := m.collectCycleTargets(); len(got) != 0 {
		t.Fatalf("unresolved selection: got %v", got)
	}
}

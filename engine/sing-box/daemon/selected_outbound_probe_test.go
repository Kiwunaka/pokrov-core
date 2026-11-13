package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
)

type probeLeaf struct {
	adapter.Outbound
	tag, kind, dependency string
}

func (p probeLeaf) Tag() string  { return p.tag }
func (p probeLeaf) Type() string { return p.kind }
func (p probeLeaf) Dependencies() []string {
	if p.dependency == "" {
		return nil
	}
	return []string{p.dependency}
}

type probeGroup struct {
	adapter.OutboundGroup
	selected atomic.Value
}

func (p *probeGroup) Type() string { return C.TypeSelector }
func (p *probeGroup) Now() string  { return p.selected.Load().(string) }

func TestAndroidCarrierSelectedStartupBudget(t *testing.T) {
	group := &probeGroup{}
	group.selected.Store("proxy")
	leaf := probeLeaf{tag: "proxy", kind: C.TypeVLESS, dependency: "carrier"}
	carrier := probeLeaf{tag: "carrier", kind: C.TypeDNSTT}
	lookup := func(tag string) (adapter.Outbound, bool) {
		switch tag {
		case "select":
			return group, true
		case "proxy":
			return leaf, true
		case "carrier":
			return carrier, true
		default:
			return nil, false
		}
	}
	selected, found := selectedProbeLeaf("select", lookup)
	if !found {
		t.Fatal("selected VLESS leaf was not found")
	}
	for _, kind := range []string{C.TypeDNSTT, C.TypeSlipstream, "vk"} {
		carrier.kind = kind
		if selectedStartupProbeTimeout("android", selected, lookup) != 60*time.Second {
			t.Fatalf("Android %s carrier did not get its startup budget", kind)
		}
	}
	if selectedStartupProbeTimeout("windows", selected, lookup) != C.TCPTimeout {
		t.Fatal("Windows startup budget changed")
	}
	carrier.kind = C.TypePsiphon
	if selectedStartupProbeTimeout("windows", selected, lookup) != 60*time.Second || selectedStartupProbeTimeout("android", selected, lookup) != 60*time.Second {
		t.Fatal("Psiphon did not get its startup budget")
	}
	carrier.kind = C.TypeWARP
	if selectedStartupProbeTimeout("windows", selected, lookup) != 30*time.Second || selectedStartupProbeTimeout("android", carrier, lookup) != 30*time.Second {
		t.Fatal("WARP did not get its startup budget")
	}
	leaf.dependency = ""
	selected, found = selectedProbeLeaf("select", lookup)
	if !found || selectedStartupProbeTimeout("android", selected, lookup) != C.TCPTimeout {
		t.Fatal("ordinary Android startup budget changed")
	}
}

func TestSelectedStartupDeadlineKeepsObservedStage(t *testing.T) {
	for _, expected := range []struct {
		stage urltest.ProbeStage
		text  string
	}{
		{urltest.ProbeStageConnect, "URL probe connection failed"},
		{urltest.ProbeStageTLS, "URL probe TLS negotiation failed"},
		{urltest.ProbeStageResponse, "URL probe response failed"},
	} {
		var stage atomic.Uint32
		stage.Store(uint32(expected.stage) + 1)
		err := selectedStartupDeadlineError(context.DeadlineExceeded, &stage)
		var detail *urltest.ProbeError
		if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &detail) ||
			detail.Stage != expected.stage || err.Error() != expected.text {
			t.Fatalf("deadline lost stage %d: %v", expected.stage, err)
		}
	}
	var cleanup atomic.Uint32
	if err := selectedStartupDeadlineError(context.DeadlineExceeded, &cleanup); err != context.DeadlineExceeded {
		t.Fatalf("cleanup acquired a false IO stage: %v", err)
	}
}

func TestSelectedProbeCannotConfirmChangedRouteOrDirectLeaf(t *testing.T) {
	group := &probeGroup{}
	group.selected.Store("a")
	lookup := func(tag string) (adapter.Outbound, bool) {
		if tag == "select" {
			return group, true
		}
		kind := "vless"
		if tag == "direct" {
			kind = C.TypeDirect
		}
		return probeLeaf{tag: tag, kind: kind}, true
	}
	healthy, err := probeSelectedOutbound(context.Background(), "select", lookup,
		func(_ context.Context, outbound adapter.Outbound) (uint16, error) {
			if outbound.Tag() != "a" {
				t.Error("probe did not capture selected leaf")
			}
			group.selected.Store("b")
			return 10, nil
		})
	if healthy || err == nil || err.Error() != "selected route probe unavailable" {
		t.Fatal("success for A confirmed the replacement B route")
	}
	healthy, err = probeSelectedOutbound(context.Background(), "select", lookup,
		func(_ context.Context, outbound adapter.Outbound) (uint16, error) {
			if outbound.Tag() != "b" {
				t.Error("fresh probe did not capture the replacement leaf")
			}
			return 10, nil
		})
	if !healthy || err != nil {
		t.Fatal("fresh proof for the replacement leaf was unavailable")
	}
	healthy, err = probeRuntimeEgress(context.Background(), time.Second, func() bool { return false }, "select", lookup,
		func(context.Context, adapter.Outbound) (uint16, error) {
			return 0, nil // A verified HEAD response can finish within one millisecond.
		})
	if !healthy || err != nil {
		t.Fatal("zero-millisecond runtime proof was rejected")
	}
	networkFailure := errors.New("URL probe connection failed")
	group.selected.Store("a")
	healthy, err = probeSelectedOutbound(context.Background(), "select", lookup,
		func(context.Context, adapter.Outbound) (uint16, error) {
			group.selected.Store("b")
			return 0, networkFailure
		})
	if healthy || !errors.Is(err, networkFailure) {
		t.Fatal("route change reclassified a real network failure")
	}
	for _, tag := range []string{"direct", "select"} {
		group.selected.Store(tag)
		if _, ok := selectedProbeLeaf("select", lookup); ok {
			t.Fatal("direct or cyclic selection supplied protected egress")
		}
	}
	leaf := &probeLeaf{tag: "same-tag", kind: "hysteria2"}
	healthy, err = probeSelectedOutbound(context.Background(), leaf.tag,
		func(string) (adapter.Outbound, bool) { return leaf, true },
		func(context.Context, adapter.Outbound) (uint16, error) {
			leaf = &probeLeaf{tag: "same-tag", kind: "hysteria2"}
			return 10, nil
		})
	if healthy || err == nil || err.Error() != "selected route probe unavailable" {
		t.Fatal("old leaf confirmed its replacement with the same tag")
	}
}

func TestRuntimeEgressAllowsSlowProofAndStillCancels(t *testing.T) {
	leaf := &probeLeaf{tag: "proxy", kind: "vless"}
	lookup := func(string) (adapter.Outbound, bool) { return leaf, true }
	neverInterrupted := func() bool { return false }
	probe := func(ctx context.Context, _ adapter.Outbound) (uint16, error) {
		timer := time.NewTimer(3100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return 3100, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	healthy, err := probeRuntimeEgress(context.Background(), C.TCPTimeout, neverInterrupted, "proxy", lookup, probe)
	if !healthy || err != nil {
		t.Fatalf("slow protected egress was rejected: healthy=%v err=%v", healthy, err)
	}
	if _, err = probeRuntimeEgress(context.Background(), C.TCPTimeout+time.Millisecond, neverInterrupted, "proxy", lookup, probe); err == nil {
		t.Fatal("runtime egress accepted a budget beyond the startup limit")
	}
	blocked := func(ctx context.Context, _ adapter.Outbound) (uint16, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	var cancelled atomic.Bool
	timer := time.AfterFunc(30*time.Millisecond, func() { cancelled.Store(true) })
	defer timer.Stop()
	if healthy, err = probeRuntimeEgress(context.Background(), C.TCPTimeout, cancelled.Load, "proxy", lookup, blocked); healthy || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled egress was not stopped: healthy=%v err=%v", healthy, err)
	}
	if healthy, err = probeRuntimeEgress(context.Background(), 30*time.Millisecond, neverInterrupted, "proxy", lookup, blocked); healthy || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unreachable egress did not time out: healthy=%v err=%v", healthy, err)
	}
}

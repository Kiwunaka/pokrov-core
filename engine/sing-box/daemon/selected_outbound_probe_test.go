package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

type probeLeaf struct {
	adapter.Outbound
	tag, kind string
}

func (p probeLeaf) Tag() string  { return p.tag }
func (p probeLeaf) Type() string { return p.kind }

type probeGroup struct {
	adapter.OutboundGroup
	selected atomic.Value
}

func (p *probeGroup) Type() string { return C.TypeSelector }
func (p *probeGroup) Now() string  { return p.selected.Load().(string) }

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
	if healthy || err != nil {
		t.Fatal("success for A confirmed the replacement B route")
	}
	for _, tag := range []string{"direct", "select"} {
		group.selected.Store(tag)
		if _, ok := selectedProbeLeaf("select", lookup); ok {
			t.Fatal("direct or cyclic selection supplied protected egress")
		}
	}
}

func TestSelectedProbeLateSuccessAfterTimeoutCannotSettleNextCall(t *testing.T) {
	lookup := func(tag string) (adapter.Outbound, bool) {
		return probeLeaf{tag: tag, kind: "vless"}, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	startedA, releaseA := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-releaseA:
		default:
			close(releaseA)
		}
	}()
	resultA := make(chan bool, 1)
	go func() {
		healthy, _ := probeSelectedOutbound(ctx, "a", lookup,
			func(context.Context, adapter.Outbound) (uint16, error) {
				close(startedA)
				<-releaseA // synthetic late success ignores cancellation
				return 10, nil
			})
		resultA <- healthy
	}()
	<-startedA
	select {
	case healthy := <-resultA:
		if healthy {
			t.Fatal("timed out probe supplied proof")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out probe did not settle")
	}
	startedB, releaseB := make(chan struct{}), make(chan struct{})
	resultB := make(chan bool, 1)
	go func() {
		healthy, _ := probeSelectedOutbound(context.Background(), "b", lookup,
			func(context.Context, adapter.Outbound) (uint16, error) {
				close(startedB)
				<-releaseB
				return 65535, nil
			})
		resultB <- healthy
	}()
	<-startedB
	close(releaseA)
	select {
	case <-resultB:
		t.Fatal("late A result settled the pending B probe")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseB)
	if <-resultB {
		t.Fatal("timeout sentinel confirmed B")
	}
	healthy, err := probeSelectedOutbound(context.Background(), "b", lookup,
		func(context.Context, adapter.Outbound) (uint16, error) { return 10, nil })
	if !healthy || err != nil {
		t.Fatal("fresh successful captured call did not supply proof")
	}
}

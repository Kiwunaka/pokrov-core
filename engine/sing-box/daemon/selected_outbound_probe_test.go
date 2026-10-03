package daemon

import (
	"context"
	"errors"
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

func TestSelectedProbeLateSuccessAfterTimeoutCannotSettleNextCall(t *testing.T) {
	lookup := func(tag string) (adapter.Outbound, bool) {
		return probeLeaf{tag: tag, kind: "vless"}, true
	}
	startedA, releaseA := make(chan struct{}), make(chan struct{})
	var probeContext context.Context
	defer func() {
		select {
		case <-releaseA:
		default:
			close(releaseA)
		}
	}()
	resultA := make(chan bool, 1)
	go func() {
		healthy, err := probeRuntimeEgress(context.Background(), 30*time.Millisecond,
			func() bool { return false }, "a", lookup,
			func(ctx context.Context, _ adapter.Outbound) (uint16, error) {
				probeContext = ctx
				close(startedA)
				<-releaseA // synthetic late success ignores cancellation
				return 10, nil
			})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Error("periodic deadline did not reach the probe context")
		}
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
	if !errors.Is(probeContext.Err(), context.DeadlineExceeded) {
		t.Fatal("detached transport kept an uncancelled probe context")
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

func TestRuntimeProbeCancellationJoinsCallbackAndUsesEndpointBudget(t *testing.T) {
	// An endpoint uses the same call budget, with no readiness/init wait.
	leaf := &probeLeaf{tag: "awg", kind: "awg"}
	lookup := func(string) (adapter.Outbound, bool) { return leaf, true }
	var cancelled atomic.Bool
	var callbackCalls atomic.Int32
	started, workerDone := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		healthy, err := probeRuntimeEgress(context.Background(), 3*time.Second,
			func() bool { callbackCalls.Add(1); return cancelled.Load() }, "awg", lookup,
			func(ctx context.Context, selected adapter.Outbound) (uint16, error) {
				if selected != leaf {
					t.Error("endpoint was not the captured protected target")
				}
				close(started)
				<-ctx.Done()
				close(workerDone)
				return 10, nil // Late transport success cannot override cancellation.
			})
		if healthy {
			t.Error("cancelled periodic check supplied proof")
		}
		result <- err
	}()
	<-started
	cancelled.Store(true)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("native cancellation did not cancel the Go probe")
		}
	case <-time.After(time.Second):
		t.Fatal("native cancellation waited for the startup budget")
	}
	<-workerDone
	callsAtReturn := callbackCalls.Load()
	time.Sleep(30 * time.Millisecond)
	if callbackCalls.Load() != callsAtReturn {
		t.Fatal("callback watcher survived the native invocation")
	}
	for _, timeout := range []time.Duration{0, 3001 * time.Millisecond} {
		_, err := probeRuntimeEgress(context.Background(), timeout, func() bool { return false }, "awg", lookup,
			func(context.Context, adapter.Outbound) (uint16, error) {
				t.Fatal("invalid periodic budget reached the transport")
				return 0, nil
			})
		if err == nil {
			t.Fatal("invalid periodic budget was accepted")
		}
	}
}

func TestRuntimeProbeDoesNotWaitForClosingInstance(t *testing.T) {
	s := NewStartedService(ServiceOptions{Context: context.Background(), LogMaxLines: 1})
	s.serviceAccess.Lock()
	defer s.serviceAccess.Unlock()
	done := make(chan bool, 1)
	go func() {
		healthy, err := s.ProbeRuntimeEgressResult("select", 3*time.Second, func() bool { return false })
		done <- !healthy && err != nil
	}()
	select {
	case rejected := <-done:
		if !rejected {
			t.Fatal("busy lifecycle supplied proof")
		}
	case <-time.After(time.Second):
		t.Fatal("periodic probe blocked on lifecycle teardown")
	}
}

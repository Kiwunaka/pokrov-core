package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

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

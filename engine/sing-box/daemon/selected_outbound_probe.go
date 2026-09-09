package daemon

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
)

// ProbeSelectedOutboundResult tests the captured selected leaf, without using
// the shared URL-test history as a response channel. The host still owns the
// attempt/generation fence around this call.
func (s *StartedService) ProbeSelectedOutboundResult(tag string) (bool, error) {
	s.serviceAccess.RLock()
	if s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		s.serviceAccess.RUnlock()
		return false, errors.New("selected route probe unavailable")
	}
	instance := s.instance
	s.serviceAccess.RUnlock()
	ctx, cancel := context.WithTimeout(instance.ctx, C.TCPTimeout)
	defer cancel()
	healthy, err := probeSelectedOutbound(ctx, tag, instance.instance.Outbound().Outbound,
		func(ctx context.Context, outbound adapter.Outbound) (uint16, error) {
			return urltest.URLTest(ctx, "", outbound)
		})
	s.serviceAccess.RLock()
	current := s.serviceStatus.Status == ServiceStatus_STARTED && s.instance == instance
	s.serviceAccess.RUnlock()
	return healthy && current, err
}

func selectedProbeLeaf(tag string, lookup func(string) (adapter.Outbound, bool)) (adapter.Outbound, bool) {
	visited := make(map[string]bool)
	for len(visited) < 16 && tag != "" && !visited[tag] {
		visited[tag] = true
		outbound, found := lookup(tag)
		if !found || outbound == nil {
			return nil, false
		}
		if group, ok := outbound.(adapter.OutboundGroup); ok {
			if outbound.Type() != C.TypeSelector && outbound.Type() != C.TypeURLTest {
				return nil, false
			}
			tag = group.Now()
			continue
		}
		// A reachable direct/block/DNS leaf is not protected proxy egress.
		switch outbound.Type() {
		case C.TypeDirect, C.TypeBlock, C.TypeDNS:
			return nil, false
		}
		return outbound, true
	}
	return nil, false
}

func probeSelectedOutbound(ctx context.Context, tag string,
	lookup func(string) (adapter.Outbound, bool),
	probe func(context.Context, adapter.Outbound) (uint16, error),
) (bool, error) {
	selected, found := selectedProbeLeaf(tag, lookup)
	if !found || ctx.Err() != nil {
		return false, errors.New("selected route probe target unavailable")
	}
	type result struct {
		delay uint16
		err   error
	}
	// A late return belongs only to this call, even after its timeout.
	done := make(chan result, 1)
	go func() {
		delay, err := probe(ctx, selected)
		done <- result{delay, err}
	}()
	select {
	case value := <-done:
		current, ok := selectedProbeLeaf(tag, lookup)
		return value.err == nil && ctx.Err() == nil && value.delay > 0 &&
			value.delay < 65535 && ok && current.Tag() == selected.Tag(), value.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/pokrov/smartaccess"
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

// ProbeRuntimeEgressResult is the short periodic check of the active protected
// route. Startup verification retains its separate initialization budgets.
func (s *StartedService) ProbeRuntimeEgressResult(tag string, timeout time.Duration, interrupted func() bool) (bool, error) {
	// CloseService can hold this lock while shared transport workers settle.
	// A periodic check must not wait for that lifecycle operation.
	if !s.serviceAccess.TryRLock() {
		return false, errors.New("runtime egress probe unavailable")
	}
	if s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		s.serviceAccess.RUnlock()
		return false, errors.New("runtime egress probe unavailable")
	}
	instance := s.instance
	s.serviceAccess.RUnlock()
	healthy, err := probeRuntimeEgress(instance.ctx, timeout, interrupted, tag,
		instance.instance.Outbound().Outbound,
		func(ctx context.Context, outbound adapter.Outbound) (uint16, error) {
			return urltest.URLTest(ctx, "", outbound)
		})
	if !s.serviceAccess.TryRLock() {
		return false, err
	}
	current := s.serviceStatus.Status == ServiceStatus_STARTED && s.instance == instance
	s.serviceAccess.RUnlock()
	return healthy && current && instance.ctx.Err() == nil, err
}

func probeRuntimeEgress(parent context.Context, timeout time.Duration, interrupted func() bool,
	tag string, lookup func(string) (adapter.Outbound, bool),
	probe func(context.Context, adapter.Outbound) (uint16, error),
) (healthy bool, err error) {
	if timeout <= 0 || timeout > 3*time.Second || interrupted == nil {
		return false, errors.New("invalid runtime egress probe request")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if interrupted() {
		return false, context.Canceled
	}
	watchStop, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-watchStop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if interrupted() {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		close(watchStop)
		<-watchDone // Never retain the native cancellation callback after return.
		if ctx.Err() != nil {
			healthy, err = false, ctx.Err()
		} else if interrupted() {
			healthy, err = false, context.Canceled
		}
	}()
	// Endpoint tags already resolve through the outbound manager. In particular,
	// periodic AWG probes do not add the startup endpoint initialization wait.
	return probeSelectedOutbound(ctx, tag, lookup, probe)
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
		var delay uint16
		var err error
		if anchor, ok := selected.(*smartaccess.Outbound); ok {
			delay, err = anchor.ProbeServiceReadiness(ctx)
		} else {
			delay, err = probe(ctx, selected)
		}
		done <- result{delay, err}
	}()
	select {
	case value := <-done:
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		current, ok := selectedProbeLeaf(tag, lookup)
		succeeded := value.err == nil && ctx.Err() == nil && value.delay > 0 && value.delay < 65535
		if succeeded && (!ok || current != selected) {
			return false, errors.New("selected route probe unavailable")
		}
		return succeeded && ok && current == selected, value.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

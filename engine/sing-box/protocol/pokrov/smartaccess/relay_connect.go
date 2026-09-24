package smartaccess

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// Relay TCP establishment only. Neither a successful dial nor this breaker
// proves destination TLS, login, streaming or service health.
type relayConnectState struct {
	failures []time.Time
	openUntil time.Time
	probing bool
	epoch uint64
}

func validRelayConnectPolicy(policy *option.PokrovRelayConnectPolicy) bool {
	if policy == nil { return true }
	if policy.FailureThreshold < 1 || policy.FailureThreshold > 10000 || policy.MaxAttempts < 1 || policy.MaxAttempts > 8 {
		return false
	}
	for _, value := range []int{policy.FailureWindowMS, policy.CooldownMS, policy.ConnectTimeoutMS, policy.TotalTimeoutMS} {
		if value < 1 || value > 600000 { return false }
	}
	return policy.ConnectTimeoutMS <= policy.TotalTimeoutMS
}

func (h *Outbound) connectRelay(ctx context.Context, lease *leaseAuthorization) (net.Conn, error) {
	if h.relayPolicy == nil {
		// Absence of an approved budget preserves one pinned dial, no retries.
		conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.relays[0])
		if err == nil && ctx.Err() != nil {
			_ = conn.Close()
			return nil, errLease
		}
		return conn, err
	}
	visited := make(map[int]bool, len(h.relays))
	for attempt := 0; attempt < h.relayPolicy.MaxAttempts; attempt++ {
		if ctx.Err() != nil { return nil, errLease }
		index, epoch, probe, ok := h.reserveRelay(lease, visited, attempt > 0)
		if !ok { return nil, errLease }
		visited[index] = true
		dialCtx, cancel := context.WithTimeout(ctx, time.Duration(h.relayPolicy.ConnectTimeoutMS)*time.Millisecond)
		conn, err := h.dialer.DialContext(dialCtx, N.NetworkTCP, h.relays[index])
		withinAttempt := dialCtx.Err() == nil
		cancel()
		cancelled := ctx.Err() != nil
		accepted := h.completeRelay(index, epoch, probe, err == nil && withinAttempt, cancelled)
		if err == nil {
			if accepted && ctx.Err() == nil { return conn, nil }
			_ = conn.Close()
		}
		if cancelled { return nil, errLease }
	}
	return nil, errLease
}

// Reserve one half-open attempt per endpoint. The original flow admission has
// already consumed its first quota slot; every extra relay dial consumes another.
func (h *Outbound) reserveRelay(lease *leaseAuthorization, visited map[int]bool, extra bool) (int, uint64, bool, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if !h.admitsLeaseLocked(lease, now) { return 0, 0, false, false }
	for len(h.attempts) > 0 && now.Sub(h.attempts[0]) >= time.Minute { h.attempts = h.attempts[1:] }
	if extra && len(h.attempts) >= h.maxNew { return 0, 0, false, false }
	for offset := 0; offset < len(h.relays); offset++ {
		index := (h.preferredRelay + offset) % len(h.relays)
		if visited[index] { continue }
		state := &h.relayStates[index]
		probe := !state.openUntil.IsZero()
		if probe && (state.probing || now.Before(state.openUntil)) { continue }
		if probe { state.probing = true }
		if extra { h.attempts = append(h.attempts, now) }
		return index, state.epoch, probe, true
	}
	return 0, 0, false, false
}

func (h *Outbound) completeRelay(index int, epoch uint64, probe, success, cancelled bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := &h.relayStates[index]
	// A late success cannot close a breaker opened by a newer failure sequence.
	if state.epoch != epoch { return false }
	if probe { state.probing = false }
	if cancelled { return false } // User/lease cancellation is not provider failure.
	if success {
		state.failures = nil
		if probe { state.openUntil = time.Time{}; state.epoch++ }
		h.preferredRelay = index
		return true
	}
	now := time.Now()
	window := time.Duration(h.relayPolicy.FailureWindowMS) * time.Millisecond
	for len(state.failures) > 0 && now.Sub(state.failures[0]) >= window { state.failures = state.failures[1:] }
	state.failures = append(state.failures, now)
	if probe || len(state.failures) >= h.relayPolicy.FailureThreshold {
		state.failures = nil
		state.openUntil = now.Add(time.Duration(h.relayPolicy.CooldownMS) * time.Millisecond)
		state.epoch++
	}
	return false
}

package localdpi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"time"
)

// PrepareWindowsRetry replaces the complete set of current Windows holders.
// The caller serializes this operation with runtime lifecycle and admission API
// calls. New holders remain unpublished until the native owner proves them.
func PrepareWindowsRetry(holders []*Outbound, expectedIDs []string) ([]string, bool) {
	if len(holders) == 0 || len(holders) != len(expectedIDs) || len(holders) > 256 {
		return nil, false
	}
	ordered := append([]*Outbound(nil), holders...)
	seen := make(map[*Outbound]bool, len(holders))
	newIDs := make([]string, len(holders))
	for i, h := range holders {
		if h == nil || seen[h] {
			return nil, false
		}
		seen[h] = true
		var identity [16]byte
		if _, err := rand.Read(identity[:]); err != nil {
			return nil, false
		}
		newIDs[i] = hex.EncodeToString(identity[:])
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Tag() < ordered[j].Tag() })
	for _, h := range ordered {
		h.mu.Lock()
	}
	unlock := func() {
		for i := len(ordered) - 1; i >= 0; i-- {
			ordered[i].mu.Unlock()
		}
	}
	failed := false
	ids := make(map[string]bool, len(holders)*2)
	for i, h := range holders {
		state := h.admission.Load()
		if !h.windowsDirect || h.closed || h.retryPrepared || h.runtimeCtx == nil || h.runtimeCtx.Err() != nil ||
			h.admissionID != expectedIDs[i] || (state != admissionReady && state != admissionFailed) || ids[expectedIDs[i]] {
			unlock()
			return nil, false
		}
		ids[expectedIDs[i]] = true
		if state == admissionFailed && (h.failureReason == failureEarlyRead || h.failureReason == failureEarlyWrite ||
			h.failureReason == failureConnectTimeoutIPv4 || h.failureReason == failureConnectErrorIPv4) {
			failed = true
		}
	}
	for _, id := range newIDs {
		if ids[id] {
			unlock()
			return nil, false
		}
		ids[id] = true
	}
	if !failed {
		unlock()
		return nil, false
	}
	type localFlow struct {
		owner *Outbound
		flow  *flow
	}
	var flows []localFlow
	for i, h := range holders {
		h.admission.Store(admissionUnpublished)
		h.withdrawCancel()
		for f := range h.flows {
			if f.local {
				flows = append(flows, localFlow{h, f})
			}
		}
		h.admissionID = newIDs[i]
		h.admissionResolved = make(chan struct{})
		h.admissionDeadline = time.Time{} // Retry never repeats the initial YouTube wait.
		h.withdrawCtx, h.withdrawCancel = context.WithCancel(h.runtimeCtx)
		h.withdrawCompleted = false
		h.failureReason = ""
		h.retryPrepared = true
	}
	unlock()
	// Close only old local streams before the native owner stops the child.
	for _, item := range flows {
		item.owner.mu.Lock()
		if item.flow.local {
			item.flow.close()
		}
		item.owner.mu.Unlock()
	}
	return newIDs, true
}

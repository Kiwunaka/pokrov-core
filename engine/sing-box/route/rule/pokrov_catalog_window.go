package rule

import (
	"context"
	"errors"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/pokrov/smartaccess"
	"github.com/sagernet/sing/service"
)

const catalogTimeLayout = "2006-01-02T15:04:05Z"
var catalogLeaseIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var catalogServiceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type catalogRuleWindow struct {
	issuedAt  time.Time
	expiresAt time.Time
	deadline  time.Time
	expired   atomic.Bool
	leaseID string
	serviceID string
	outbounds adapter.OutboundManager
	lease *smartaccess.Outbound
	leaseGroupIDs []string
	leaseGroup *smartaccess.ServiceLeaseGroup
}

func newCatalogRuleWindow(ctx context.Context, options *option.PokrovCatalogWindow, invert bool, domains int) (*catalogRuleWindow, error) {
	if options == nil {
		return nil, nil
	}
	if invert || domains == 0 {
		return nil, errors.New("catalog_window_requires_noninverted_domain_rule")
	}
	issued, err := time.Parse(catalogTimeLayout, options.IssuedAt)
	if err != nil || issued.Year() < 1 || issued.Format(catalogTimeLayout) != options.IssuedAt {
		return nil, errors.New("catalog_window_time_invalid")
	}
	expires, err := time.Parse(catalogTimeLayout, options.ExpiresAt)
	if err != nil || expires.Year() < 1 || expires.Format(catalogTimeLayout) != options.ExpiresAt || !expires.After(issued) {
		return nil, errors.New("catalog_window_time_invalid")
	}
	now := time.Now()
	if now.Before(issued) {
		return nil, errors.New("catalog_window_not_current")
	}
	window := &catalogRuleWindow{
		issuedAt: issued, expiresAt: expires,
		// Add attaches the current process's monotonic clock. A backwards wall
		// clock adjustment cannot extend a window already admitted by this core.
		deadline: now.Add(expires.Sub(now)),
	}
	if options.LeaseID != "" {
		if !catalogLeaseIDPattern.MatchString(options.LeaseID) {
			return nil, errors.New("catalog_window_lease_invalid")
		}
		window.leaseID = options.LeaseID
		window.outbounds = service.FromContext[adapter.OutboundManager](ctx)
		if window.outbounds == nil { return nil, errors.New("catalog_window_lease_unavailable") }
	}
	if options.ServiceID != "" {
		if !catalogServiceIDPattern.MatchString(options.ServiceID) {
			return nil, errors.New("catalog_window_service_invalid")
		}
		window.serviceID = options.ServiceID
	}
	if len(options.LeaseGroup) > 0 {
		if window.leaseID == "" || window.serviceID == "" || len(options.LeaseGroup) > 16 {
			return nil, errors.New("catalog_window_group_invalid")
		}
		seen := make(map[string]bool)
		for _, id := range options.LeaseGroup {
			if !catalogLeaseIDPattern.MatchString(id) || seen[id] { return nil, errors.New("catalog_window_group_invalid") }
			seen[id] = true
		}
		if !seen[window.leaseID] { return nil, errors.New("catalog_window_group_invalid") }
		window.leaseGroupIDs = append([]string(nil), options.LeaseGroup...)
	}
	if !now.Before(expires) {
		window.expired.Store(true)
	}
	return window, nil
}

func (w *catalogRuleWindow) start() error {
	if w.leaseID == "" { return nil }
	raw, found := w.outbounds.Outbound("pokrov-smart-access-" + w.leaseID)
	lease, supported := raw.(*smartaccess.Outbound)
	if !found || !supported || lease.LeaseID() != w.leaseID {
		return errors.New("catalog_window_lease_unavailable")
	}
	w.lease = lease
	if len(w.leaseGroupIDs) != 0 {
		members := make([]*smartaccess.Outbound, 0, len(w.leaseGroupIDs))
		for _, id := range w.leaseGroupIDs {
			raw, found := w.outbounds.Outbound("pokrov-smart-access-" + id)
			member, supported := raw.(*smartaccess.Outbound)
			if !found || !supported || member.LeaseID() != id { return errors.New("catalog_window_group_unavailable") }
			members = append(members, member)
		}
		group, err := members[0].ServiceLeaseGroup(w.serviceID, members)
		if err != nil { return err }
		w.leaseGroup = group
	}
	return nil
}

func (w *catalogRuleWindow) active() bool {
	if w.expired.Load() {
		return false
	}
	if w.leaseID != "" && (w.lease == nil || !w.lease.AdmitsNewFlows()) {
		return false
	}
	now := time.Now()
	if now.Before(w.issuedAt) || !now.Before(w.expiresAt) || !now.Before(w.deadline) {
		w.expired.Store(true)
		return false
	}
	return true
}

func (w *catalogRuleWindow) selected() bool {
	return w.leaseGroup == nil || w.leaseGroup.Selected() == w.lease
}

func (w *catalogRuleWindow) smartAccessDNSFailed() bool {
	if w == nil || w.leaseGroup == nil || w.lease == nil { return false }
	w.leaseGroup.DNSFailed(w.lease)
	return true
}

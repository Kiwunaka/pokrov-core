package smartaccess

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

type readinessReceiptTransport struct{ adapter.DNSTransport }

func (*readinessReceiptTransport) Tag() string { return "readiness-doh" }

type readinessReceiptManager struct {
	adapter.DNSTransportManager
	transport adapter.DNSTransport
}

func (m *readinessReceiptManager) Transport(tag string) (adapter.DNSTransport, bool) {
	return m.transport, tag == m.transport.Tag()
}

// This checks receipt state transitions, without networking or fabricating a
// provider/browser QA result. The production stage writers own real observations.
func TestReadinessReceiptsResetAndFenceCurrentLease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	leaseID := "0123456789abcdef0123456789abcdef"
	newFixture := func() (*Outbound, *ServiceLeaseGroup, *readinessReceiptManager) {
		lease, err := newLeaseAuthorization(leaseID, now.Format(timeLayout), now.Add(time.Minute).Format(timeLayout), now.Add(2*time.Minute).Format(timeLayout))
		if err != nil {
			t.Fatal(err)
		}
		member := &Outbound{lease: lease, leases: map[string]*leaseAuthorization{leaseID: lease},
			domains: []option.PokrovSmartAccessDomain{{Name: "service.test", Match: "exact"}}, maxNew: 10, maxConcurrent: 2}
		group := &ServiceLeaseGroup{serviceID: "service", members: []*Outbound{member}, evaluated: true}
		member.serviceGroup = group
		manager := &readinessReceiptManager{transport: &readinessReceiptTransport{}}
		group.BindProbeWindow(member, true, manager.transport, func() bool { return true }, func(string) bool { return true })
		group.BindProbeWindow(member, false, nil, func() bool { return true }, func(string) bool { return true })
		return member, group, manager
	}
	begin := func(group *ServiceLeaseGroup, member *Outbound, manager *readinessReceiptManager, ctx context.Context) *serviceReadinessProbe {
		probe := group.beginReadiness(ctx, context.Background())
		group.bindReadiness(probe, member, member.LeaseID(), manager.transport, manager)
		return probe
	}
	observe := func(group *ServiceLeaseGroup, probe *serviceReadinessProbe, stage string, err error) {
		group.observeReadiness(probe, stage, time.Now(), time.Millisecond, err)
	}
	complete := func(group *ServiceLeaseGroup, probe *serviceReadinessProbe) {
		observe(group, probe, "resolver", nil)
		observe(group, probe, "dns", nil)
		observe(group, probe, "tls", nil)
		group.finishReadiness(probe, nil)
	}

	member, group, manager := newFixture()
	ctx, cancel := context.WithCancel(context.Background())
	first := begin(group, member, manager, ctx)
	complete(group, first)
	if receipt := member.ReadServiceLeaseSelection().Readiness; receipt.Status != "pass" || len(receipt.Stages) != 3 || receipt.CompletedAtMS == nil || receipt.FallbackGuardClosed {
		t.Fatal("completed current receipts were unavailable")
	}
	cancel() // The normal caller releases its completed probe timeout context.
	if member.ReadServiceLeaseSelection().Readiness.Status != "pass" {
		t.Fatal("completed probe cleanup discarded real receipts")
	}
	periodic := begin(group, member, manager, context.Background())
	complete(group, periodic)
	if receipt := member.ReadServiceLeaseSelection().Readiness; receipt.Status != "pass" || receipt.FallbackGuardClosed {
		t.Fatal("later successful periodic probe invalidated the same live candidate")
	}
	first = periodic

	second := begin(group, member, manager, context.Background())
	if second.ProbeID != first.ProbeID+1 || len(second.Stages) != 0 || second.CompletedAtMS != nil || second.Status != "pending" {
		t.Fatal("new probe retained a previous stage or completion")
	}
	observe(group, second, "resolver", nil)
	dnsFailure := errors.New("DNS failed")
	observe(group, second, "dns", dnsFailure)
	group.finishReadiness(second, dnsFailure)
	observe(group, first, "tls", nil) // A late old observation cannot finish the new probe.
	receipt := member.ReadServiceLeaseSelection().Readiness
	if receipt.ProbeID != second.ProbeID || receipt.Status != "failure" || !receipt.FallbackGuardClosed ||
		len(receipt.Stages) != 2 || receipt.Stages[1].Stage != "dns" || receipt.Stages[1].Result != "failure" {
		t.Fatal("partial DNS failure combined with stale TLS success")
	}

	member, group, manager = newFixture()
	first = begin(group, member, manager, context.Background())
	complete(group, first)
	nextID := "1123456789abcdef0123456789abcdef"
	if renewed, err := member.RenewLease(leaseID, nextID, now.Format(timeLayout), now.Add(2*time.Minute).Format(timeLayout), now.Add(3*time.Minute).Format(timeLayout), func(time.Time) error { return nil }); !renewed || err != nil {
		t.Fatal("lease renewal fixture failed")
	}
	second = begin(group, member, manager, context.Background())
	complete(group, second)
	receipt = member.ReadServiceLeaseSelection().Readiness
	if receipt.LeaseID != nextID || receipt.Status != "failure" || !receipt.FallbackGuardClosed {
		t.Fatal("new probe erased the old captured lease invalidation")
	}

	member, group, manager = newFixture()
	first = begin(group, member, manager, context.Background())
	complete(group, first)
	group.ObserveScopedRuleBypass(member, "unrelated.test")
	if member.ReadServiceLeaseSelection().Readiness.Status != "pass" {
		t.Fatal("unrelated traffic closed the service guard")
	}
	second = group.beginReadiness(context.Background(), context.Background())
	group.ObserveScopedRuleBypass(member, "service.test") // Browser walk during probe begin -> bind.
	group.bindReadiness(second, member, member.LeaseID(), manager.transport, manager)
	complete(group, second)
	if receipt = member.ReadServiceLeaseSelection().Readiness; receipt.Status != "failure" || !receipt.FallbackGuardClosed {
		t.Fatal("probe reset lost a captured service rule bypass before binding")
	}

	member, group, manager = newFixture()
	ctx, cancel = context.WithCancel(context.Background())
	first = begin(group, member, manager, ctx)
	observe(group, first, "resolver", nil)
	observe(group, first, "dns", nil)
	cancel()
	observe(group, first, "tls", nil)
	group.finishReadiness(first, nil)
	if receipt = member.ReadServiceLeaseSelection().Readiness; receipt.Status != "failure" || len(receipt.Stages) != 2 || !receipt.FallbackGuardClosed {
		t.Fatal("cancelled partial probe accepted a late TLS success")
	}
}

package smartaccess

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
)

// Written before the flow's onClose notification; read only after it settles.
// Ordinary relay connections retain their existing public error behavior.
type serviceProbeState struct {
	connected    bool
	connectError error
}

// ProbeServiceReadiness tests only the current service's bound DoH and visible
// SNI TLS relay. It neither proves an HTTP feature nor supplies a raw dialer.
// The explicit DoH transport does not assert an ordinary DNS rule walk.
func (h *Outbound) ProbeServiceReadiness(ctx context.Context) (delayResult uint16, probeError error) {
	h.mu.Lock()
	group := h.serviceGroup
	h.mu.Unlock()
	if group == nil {
		return 0, errLease
	}
	probe := group.beginReadiness(ctx, h.ctx)
	defer func() { group.finishReadiness(probe, probeError) }()
	if ctx.Err() != nil || h.ctx.Err() != nil {
		return 0, errLease
	}
	member := group.Selected()
	if member == nil {
		if err := group.probeUnavailableError(service.FromContext[adapter.DNSTransportManager](h.ctx)); err != nil && ctx.Err() == nil && h.ctx.Err() == nil {
			return 0, err
		}
		return 0, errLease
	}
	leaseID := member.LeaseID()
	domain := member.domains[0].Name
	transport, scoped := group.probeScope(member, domain, true)
	manager := service.FromContext[adapter.DNSTransportManager](h.ctx)
	resolver := service.FromContext[adapter.DNSRouter](h.ctx)
	group.bindReadiness(probe, member, leaseID, transport, manager)
	if !scoped || manager == nil || resolver == nil {
		return 0, errScope
	}
	current := func(selected bool) bool {
		bound, ok := manager.Transport(transport.Tag())
		active, scoped := group.probeScope(member, domain, selected)
		return ctx.Err() == nil && h.ctx.Err() == nil && member.LeaseID() == leaseID &&
			ok && bound == transport && scoped && active == transport
	}
	unavailable := func() error {
		if ctx.Err() == nil && h.ctx.Err() == nil && member.LeaseID() == leaseID {
			if err := group.probeUnavailableError(manager); err != nil {
				return err
			}
		}
		return errLease
	}
	if !current(true) {
		return 0, unavailable()
	}
	started := time.Now()
	dnsContext := adapter.ContextWithDNSReadinessObserver(ctx, func(observedTransport adapter.DNSTransport, observedAt time.Time, duration time.Duration, err error) {
		if observedTransport != transport {
			return
		}
		group.observeReadiness(probe, "resolver", observedAt, duration, err)
	})
	addresses, err := resolver.Lookup(dnsContext, domain, adapter.DNSQueryOptions{
		Transport: transport, Strategy: C.DomainStrategyIPv4Only,
		DisableCache: true, DisableOptimisticCache: true,
	})
	if !current(false) {
		return 0, unavailable()
	}
	if err != nil {
		failure := &urltest.ProbeError{Stage: urltest.ProbeStageDNS, Err: err}
		group.observeReadiness(probe, "dns", time.Now(), time.Since(started), failure)
		return 0, failure
	}
	if !current(true) {
		return 0, unavailable()
	}
	if len(addresses) == 0 {
		failure := &urltest.ProbeError{Stage: urltest.ProbeStageDNS, Err: errScope}
		group.observeReadiness(probe, "dns", time.Now(), time.Since(started), failure)
		return 0, failure
	}
	for _, address := range addresses {
		owned := false
		for _, relay := range member.relays {
			if address.Is4() && address == relay.Addr {
				owned = true
				break
			}
		}
		if !owned {
			failure := &urltest.ProbeError{Stage: urltest.ProbeStageDNS, Err: errScope}
			group.observeReadiness(probe, "dns", time.Now(), time.Since(started), failure)
			return 0, failure
		}
	}
	group.observeReadiness(probe, "dns", time.Now(), time.Since(started), nil)
	client, incoming := net.Pipe()
	stopClose := context.AfterFunc(ctx, func() { _ = client.Close(); _ = incoming.Close() })
	done := make(chan error, 1)
	var observation serviceProbeState
	go member.newConnection(ctx, incoming, adapter.InboundContext{
		Network: "tcp", Destination: M.Socksaddr{Fqdn: domain, Port: 443},
	}, func(err error) { done <- err }, &observation)
	tlsClient := tls.Client(client, &tls.Config{
		ServerName: domain, RootCAs: adapter.RootPoolFromContext(h.ctx),
		Time: ntp.TimeFuncFromContext(h.ctx), MinVersion: tls.VersionTLS12,
	})
	tlsStarted := time.Now()
	err = tlsClient.HandshakeContext(ctx)
	tlsObservedAt, tlsDuration := time.Now(), time.Since(tlsStarted)
	// Closing the raw pipe avoids an extra TLS close-notify budget. The actual
	// relay flow and its connection workers settle before the observation read.
	_ = client.Close()
	_ = incoming.Close()
	flowError := <-done
	stopClose()
	// A real transport failure may retire a breaker member, but expired,
	// revoked or replaced authority is never reclassified as that failure.
	if !current(false) {
		if ctx.Err() != nil {
			return 0, context.Cause(ctx)
		}
		return 0, unavailable()
	}
	if observation.connectError != nil {
		group.observeReadiness(probe, "tls", tlsObservedAt, tlsDuration, &urltest.ProbeError{Stage: urltest.ProbeStageConnect, Err: observation.connectError})
		return 0, &urltest.ProbeError{Stage: urltest.ProbeStageConnect, Err: observation.connectError}
	}
	if err != nil {
		group.observeReadiness(probe, "tls", tlsObservedAt, tlsDuration, &urltest.ProbeError{Stage: urltest.ProbeStageTLS, Err: err})
		if !observation.connected {
			if flowError != nil {
				return 0, flowError
			}
			return 0, errLease
		}
		return 0, &urltest.ProbeError{Stage: urltest.ProbeStageTLS, Err: err}
	}
	if !current(true) {
		return 0, unavailable()
	}
	group.observeReadiness(probe, "tls", tlsObservedAt, tlsDuration, nil)
	delay := time.Since(started).Milliseconds()
	if delay < 1 {
		delay = 1
	}
	if delay > 65534 {
		delay = 65534
	}
	return uint16(delay), nil
}

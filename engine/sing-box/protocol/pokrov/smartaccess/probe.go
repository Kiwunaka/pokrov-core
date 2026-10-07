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
func (h *Outbound) ProbeServiceReadiness(ctx context.Context) (uint16, error) {
	h.mu.Lock()
	group := h.serviceGroup
	h.mu.Unlock()
	if group == nil || ctx.Err() != nil || h.ctx.Err() != nil {
		return 0, errLease
	}
	member := group.Selected()
	if member == nil {
		if group.probeGrantsExpired(service.FromContext[adapter.DNSTransportManager](h.ctx)) &&
			ctx.Err() == nil && h.ctx.Err() == nil {
			return 0, &urltest.ProbeError{Stage: urltest.ProbeStageLeaseExpired, Err: errLease}
		}
		return 0, errLease
	}
	leaseID := member.LeaseID()
	domain := member.domains[0].Name
	transport, scoped := group.probeScope(member, domain, true)
	manager := service.FromContext[adapter.DNSTransportManager](h.ctx)
	resolver := service.FromContext[adapter.DNSRouter](h.ctx)
	if !scoped || manager == nil || resolver == nil {
		return 0, errScope
	}
	current := func(selected bool) bool {
		bound, ok := manager.Transport(transport.Tag())
		active, scoped := group.probeScope(member, domain, selected)
		return ctx.Err() == nil && h.ctx.Err() == nil && member.LeaseID() == leaseID &&
			ok && bound == transport && scoped && active == transport
	}
	if !current(true) {
		return 0, errLease
	}
	started := time.Now()
	addresses, err := resolver.Lookup(ctx, domain, adapter.DNSQueryOptions{
		Transport: transport, Strategy: C.DomainStrategyIPv4Only,
		DisableCache: true, DisableOptimisticCache: true,
	})
	if !current(false) {
		return 0, errLease
	}
	if err != nil {
		return 0, &urltest.ProbeError{Stage: urltest.ProbeStageDNS, Err: err}
	}
	if !current(true) {
		return 0, errLease
	}
	if len(addresses) == 0 {
		return 0, &urltest.ProbeError{Stage: urltest.ProbeStageDNS, Err: errScope}
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
			return 0, &urltest.ProbeError{Stage: urltest.ProbeStageDNS, Err: errScope}
		}
	}
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
	err = tlsClient.HandshakeContext(ctx)
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
		return 0, errLease
	}
	if observation.connectError != nil {
		return 0, &urltest.ProbeError{Stage: urltest.ProbeStageConnect, Err: observation.connectError}
	}
	if err != nil {
		if !observation.connected {
			if flowError != nil {
				return 0, flowError
			}
			return 0, errLease
		}
		return 0, &urltest.ProbeError{Stage: urltest.ProbeStageTLS, Err: err}
	}
	if !current(true) {
		return 0, errLease
	}
	delay := time.Since(started).Milliseconds()
	if delay < 1 {
		delay = 1
	}
	if delay > 65534 {
		delay = 65534
	}
	return uint16(delay), nil
}

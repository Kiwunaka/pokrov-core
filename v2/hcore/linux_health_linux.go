package hcore

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
)

type linuxHealth struct {
	DNSReady        bool `json:"dns_ready"`
	EgressValidated bool `json:"core_egress_validated"`
}

// Called only after linuxd has applied routes and resolved's per-link DNS.
// Each result belongs to this Core process and its current selected leaf.
func probeLinuxHealth(ctx context.Context) linuxHealth {
	var result linuxHealth
	dnsContext, cancelDNS := context.WithTimeout(ctx, 5*time.Second)
	addresses, err := net.DefaultResolver.LookupIPAddr(dnsContext, "api.pokrov.space")
	result.DNSReady = err == nil && len(addresses) > 0 && dnsContext.Err() == nil
	cancelDNS()
	instance := static.Box()
	if instance == nil {
		return result
	}
	manager := instance.Outbound()
	selected := linuxProtectedLeaf(manager.Default(), manager.Outbound)
	if selected == nil {
		return result
	}
	probeContext, cancelProbe := context.WithTimeout(ctx, 10*time.Second)
	defer cancelProbe()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return selected.DialContext(ctx, network, M.ParseSocksaddr("api.pokrov.space:443"))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequestWithContext(probeContext, http.MethodGet, "https://api.pokrov.space/api/public/authenticated-egress-probe", nil)
	response, err := client.Do(request)
	if err != nil {
		return result
	}
	defer response.Body.Close()
	current := linuxProtectedLeaf(manager.Default(), manager.Outbound)
	result.EgressValidated = response.StatusCode == http.StatusNoContent &&
		response.Header.Get("X-Pokrov-Egress-Probe") == "pokrov-authenticated-egress-v1" &&
		probeContext.Err() == nil && current != nil && current.Tag() == selected.Tag()
	return result
}

func linuxProtectedLeaf(outbound adapter.Outbound, lookup func(string) (adapter.Outbound, bool)) adapter.Outbound {
	seen := make(map[string]bool)
	for outbound != nil && len(seen) < 16 && !seen[outbound.Tag()] {
		seen[outbound.Tag()] = true
		if group, ok := outbound.(adapter.OutboundGroup); ok {
			if outbound.Type() != C.TypeSelector && outbound.Type() != C.TypeURLTest {
				return nil
			}
			outbound, _ = lookup(group.Now())
			continue
		}
		switch outbound.Type() {
		case C.TypeDirect, C.TypeBlock, C.TypeDNS:
			return nil
		}
		return outbound
	}
	return nil
}

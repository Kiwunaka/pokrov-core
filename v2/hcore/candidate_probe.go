package hcore

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

const (
	candidateProbeURL        = "https://api.pokrov.space/api/public/authenticated-egress-probe"
	candidatePayloadURL      = "https://api.pokrov.space/api/public/egress-probe-64k"
	candidateReserveProbeURL = "https://pokrov.space/.well-known/pokrov/egress-probe"
	candidateReserveDataURL  = "https://pokrov.space/.well-known/pokrov/egress-probe-64k.bin"
	candidateProbeMarker     = "pokrov-authenticated-egress-v1"
	candidatePayloadBytes    = 64 * 1024
)

type candidateProbeTarget struct {
	host, probeURL, payloadURL string
}

type CandidateProbeResult struct {
	Success     bool   `json:"success"`
	FailureKind string `json:"failure_kind"`
	DurationMS  int64  `json:"duration_ms"`
}

func (r CandidateProbeResult) JSON() string {
	value, _ := json.Marshal(r)
	return string(value)
}

type candidateProbeCall struct {
	cancel context.CancelFunc
	done   chan struct{}
}

var candidateProbes = struct {
	sync.Mutex
	calls map[string]*candidateProbeCall
}{calls: make(map[string]*candidateProbeCall)}
var candidateProbeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// CancelCandidateProbe waits for the registered call's sockets and instance.
// The host's interruption callback covers cancellation before registration.
func CancelCandidateProbe(id string) {
	candidateProbes.Lock()
	call := candidateProbes.calls[id]
	candidateProbes.Unlock()
	if call != nil {
		call.cancel()
		<-call.done
	}
}

// ProbeCandidate never touches the active Core, TUN, routes, or command server.
// interrupted must be thread-safe and remain callable until this call returns.
func ProbeCandidate(config, id string, timeout time.Duration, bindInterface string,
	platform libbox.PlatformInterface, interrupted func() bool) (result CandidateProbeResult) {
	started := time.Now()
	defer func() { result.DurationMS = time.Since(started).Milliseconds() }()
	result.FailureKind = "invalid_request"
	if !candidateProbeID.MatchString(id) || timeout <= 0 || timeout > 30*time.Second {
		return
	}
	ctx, cancel := context.WithTimeout(libbox.BaseContext(platform), timeout)
	defer cancel()
	if platform != nil {
		ctx = service.ContextWith[adapter.PlatformInterface](ctx, libbox.WrapPlatformInterface(platform))
	}
	call := &candidateProbeCall{cancel: cancel, done: make(chan struct{})}
	candidateProbes.Lock()
	if candidateProbes.calls[id] != nil {
		candidateProbes.Unlock()
		result.FailureKind = "duplicate_probe"
		return
	}
	candidateProbes.calls[id] = call
	candidateProbes.Unlock()
	defer func() {
		candidateProbes.Lock()
		delete(candidateProbes.calls, id)
		close(call.done)
		candidateProbes.Unlock()
	}()
	watchDone := make(chan struct{})
	watchStop := make(chan struct{})
	if interrupted != nil && interrupted() {
		cancel()
	}
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
				if interrupted != nil && interrupted() {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		close(watchStop)
		<-watchDone
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			if result.FailureKind != "data_stalled" {
				result.Success = false
				result.FailureKind = "timeout"
			}
		} else if ctx.Err() != nil {
			result.Success = false
			result.FailureKind = "cancelled"
		}
	}()
	if ctx.Err() != nil {
		return
	}
	options, target, err := candidateOptions(ctx, config, bindInterface)
	if err != nil {
		result.FailureKind = "invalid_profile"
		return
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		result.FailureKind = "invalid_profile"
		return
	}
	var closeOnce sync.Once
	closeInstance := func() { closeOnce.Do(func() { _ = instance.Close() }) }
	defer closeInstance()
	if err = instance.Start(); err != nil {
		result.FailureKind = "start_failed"
		return
	}
	// Close the isolated transport on cancellation, then join the request below.
	closeDone := make(chan struct{})
	closeStop := make(chan struct{})
	go func() {
		defer close(closeDone)
		select {
		case <-ctx.Done():
			closeInstance()
		case <-closeStop:
		}
	}()
	defer func() { close(closeStop); <-closeDone }()
	selected := candidateProtectedLeaf(target, instance.Outbound().Outbound)
	if selected == nil {
		result.FailureKind = "invalid_profile"
		return
	}
	result.FailureKind = candidateHTTPProbe(ctx, selected.DialContext)
	result.Success = result.FailureKind == ""
	return
}

// Remove host-owned state, while retaining the exact transport and DNS material.
func candidateOptions(ctx context.Context, config, bindInterface string) (option.Options, string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &raw); err != nil || raw == nil {
		return option.Options{}, "", errors.New("invalid profile")
	}
	for _, key := range []string{"_meta", "inbounds", "services", "experimental", "ntp", "custom"} {
		delete(raw, key)
	}
	raw["log"] = json.RawMessage(`{"disabled":true}`)
	encoded, _ := json.Marshal(raw)
	options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, encoded)
	if err != nil {
		return option.Options{}, "", err
	}
	if options.Route == nil {
		options.Route = &option.RouteOptions{}
	}
	protectedTag := func(tag string) bool {
		if tag == "" {
			return false
		}
		for _, outbound := range options.Outbounds {
			if outbound.Tag == tag {
				switch outbound.Type {
				case C.TypeDirect, C.TypeBlock, C.TypeDNS:
					return false
				default:
					return true
				}
			}
		}
		for _, endpoint := range options.Endpoints {
			if endpoint.Tag == tag {
				return true
			}
		}
		return false
	}
	target := options.Route.Final
	// Selected-apps routes other traffic directly. Probe the process rule's
	// protected outbound before removing host-owned route rules below.
	if !protectedTag(target) {
		target = ""
		for _, rule := range options.Route.Rules {
			if rule.Type != C.RuleTypeDefault || len(rule.DefaultOptions.ProcessName) == 0 {
				continue
			}
			candidate := rule.DefaultOptions.RouteOptions.Outbound
			if protectedTag(candidate) {
				target = candidate
				break
			}
		}
	}
	if target == "" {
		for _, outbound := range options.Outbounds {
			if outbound.Type == C.TypeSelector || outbound.Type == C.TypeURLTest {
				target = outbound.Tag
				break
			}
		}
	}
	if target == "" && len(options.Outbounds) > 0 {
		target = options.Outbounds[0].Tag
	}
	options.Route = &option.RouteOptions{Final: target, AutoDetectInterface: bindInterface == "",
		DefaultInterface: bindInterface, DefaultDomainResolver: options.Route.DefaultDomainResolver}
	// Bootstrap already materializes Russia/app DNS routing before probing.
	// Those client rule sets belong to the TUN profile, not this one-request instance.
	if options.DNS != nil {
		rules := options.DNS.Rules[:0]
		for _, rule := range options.DNS.Rules {
			if !candidateDNSUsesRuleSet(rule) {
				rules = append(rules, rule)
			}
		}
		options.DNS.Rules = rules
	}
	// Background URL tests must not race the exact candidate chosen by the host.
	for i := range options.Outbounds {
		outbound := &options.Outbounds[i]
		if group, ok := outbound.Options.(*option.URLTestOutboundOptions); ok {
			outbound.Type = C.TypeSelector
			outbound.Options = &option.SelectorOutboundOptions{Outbounds: group.Outbounds}
		}
		if wg, ok := outbound.Options.(*option.LegacyWireGuardOutboundOptions); ok {
			wg.SystemInterface = false
		}
	}
	for i := range options.Endpoints {
		switch endpoint := options.Endpoints[i].Options.(type) {
		case *option.WireGuardEndpointOptions:
			endpoint.System = false
			endpoint.ListenPort = 0
		case *option.WireGuardWARPEndpointOptions:
			endpoint.System = false
			endpoint.ListenPort = 0
		case *option.AwgEndpointOptions:
			endpoint.UseIntegratedTun = false
			endpoint.ListenPort = 0
		}
	}
	return options, target, nil
}

func candidateDNSUsesRuleSet(rule option.DNSRule) bool {
	if len(rule.DefaultOptions.RuleSet) > 0 {
		return true
	}
	for _, child := range rule.LogicalOptions.Rules {
		if candidateDNSUsesRuleSet(child) {
			return true
		}
	}
	return false
}

func candidateProtectedLeaf(tag string, lookup func(string) (adapter.Outbound, bool)) adapter.Outbound {
	seen := make(map[string]bool)
	for tag != "" && !seen[tag] {
		seen[tag] = true
		outbound, found := lookup(tag)
		if !found {
			return nil
		}
		if group, ok := outbound.(adapter.OutboundGroup); ok {
			if outbound.Type() != C.TypeSelector {
				return nil
			}
			tag = group.Now()
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

func candidateHTTPProbe(ctx context.Context, dial func(context.Context, string, M.Socksaddr) (net.Conn, error)) string {
	primary := candidateProbeTarget{"api.pokrov.space", candidateProbeURL, candidatePayloadURL}
	reserve := candidateProbeTarget{"pokrov.space", candidateReserveProbeURL, candidateReserveDataURL}
	// Leave a quarter of the caller's deadline for the static responder.
	primaryCtx := ctx
	cancel := func() {}
	if deadline, ok := ctx.Deadline(); ok {
		primaryCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)*3/4)
	}
	first := candidateProbeAt(primaryCtx, dial, primary)
	cancel()
	if first == "" || ctx.Err() != nil {
		return first
	}
	return candidateProbeAt(ctx, dial, reserve)
}

func candidateProbeAt(ctx context.Context, dial func(context.Context, string, M.Socksaddr) (net.Conn, error), target candidateProbeTarget) string {
	if kind := candidateHTTPSGet(ctx, dial, target.host, target.probeURL, false); kind != "" {
		return kind
	}
	return candidateHTTPSGet(ctx, dial, target.host, target.payloadURL, true)
}

func candidateHTTPSGet(ctx context.Context, dial func(context.Context, string, M.Socksaddr) (net.Conn, error), host, endpoint string, payload bool) string {
	// Keep dial, TLS and HTTP synchronous so no transport worker outlives cancel.
	conn, err := dial(ctx, "tcp", M.ParseSocksaddr(host+":443"))
	if err != nil {
		return "connect_failed"
	}
	defer conn.Close()
	closeDone := make(chan struct{})
	closeStop := make(chan struct{})
	go func() {
		defer close(closeDone)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-closeStop:
		}
	}()
	defer func() { close(closeStop); <-closeDone }()
	secured := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := secured.HandshakeContext(ctx); err != nil {
		return "tls_failed"
	}
	if payload {
		return candidateGET64K(ctx, secured, endpoint)
	}
	return candidateGET204(ctx, secured, endpoint)
}

func candidateGET204(ctx context.Context, conn net.Conn, endpoint string) string {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Close = true
	if err := request.Write(conn); err != nil {
		return "probe_failed"
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		return "probe_failed"
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Pokrov-Egress-Probe") != candidateProbeMarker {
		return "unexpected_status"
	}
	return ""
}

func candidateGET64K(ctx context.Context, conn net.Conn, endpoint string) string {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Close = true
	if err := request.Write(conn); err != nil {
		return "probe_failed"
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		return "probe_failed"
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Pokrov-Egress-Probe") != candidateProbeMarker ||
		response.ContentLength != candidatePayloadBytes || response.Header.Get("Content-Encoding") != "" {
		return "unexpected_status"
	}
	if _, err := io.CopyN(io.Discard, response.Body, candidatePayloadBytes); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "data_stalled"
		}
		return "probe_failed"
	}
	return ""
}

package telegramws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
)

type preparedScope struct {
	options  option.PokrovTelegramWSOutboundOptions
	deadline time.Time
	fallback map[string]string
}

var preparations = struct {
	sync.Mutex
	values map[string]preparedScope
}{values: make(map[string]preparedScope)}

// Only the native signed-catalog preparer calls this. Its exact options are
// consumed once by actual Start; a JSON field alone cannot mint permission.
func RegisterPreparation(options option.PokrovTelegramWSOutboundOptions, fallback map[string]string) (string, error) {
	if len(fallback) == 0 {
		return "", errScope
	}
	now := time.Now()
	issued, err := time.Parse(time.RFC3339, options.IssuedAt)
	if err != nil || issued.Format(time.RFC3339) != options.IssuedAt || now.Before(issued) {
		return "", errScope
	}
	expires, err := time.Parse(time.RFC3339, options.ExpiresAt)
	if err != nil || expires.Format(time.RFC3339) != options.ExpiresAt || !now.Before(expires) {
		return "", errScope
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(nonce[:])
	options.NativePreparationID = ""
	options.Datacenters = append([]option.PokrovTelegramWSDatacenter(nil), options.Datacenters...)
	for i := range options.Datacenters {
		options.Datacenters[i].Addresses = append([]string(nil), options.Datacenters[i].Addresses...)
	}
	preparations.Lock()
	defer preparations.Unlock()
	for key, value := range preparations.values {
		if !now.Before(value.deadline) {
			delete(preparations.values, key)
		}
	}
	bound := make(map[string]string, len(fallback))
	for tag, definition := range fallback {
		bound[tag] = definition
	}
	preparations.values[id] = preparedScope{options: options, deadline: now.Add(expires.Sub(now)), fallback: bound}
	return id, nil
}

func peekPreparation(options option.PokrovTelegramWSOutboundOptions) (time.Time, bool) {
	preparations.Lock()
	defer preparations.Unlock()
	proof, found := preparations.values[options.NativePreparationID]
	options.NativePreparationID = ""
	return proof.deadline, found && time.Now().Before(proof.deadline) && reflect.DeepEqual(options, proof.options)
}

type preparationContextKey struct{}

func consumePreparation(ctx context.Context, options option.PokrovTelegramWSOutboundOptions) (time.Time, bool) {
	bound, _ := ctx.Value(preparationContextKey{}).(map[string]preparedScope)
	preparations.Lock()
	defer preparations.Unlock()
	proof, found := preparations.values[options.NativePreparationID]
	checked, graphBound := bound[options.NativePreparationID]
	delete(preparations.values, options.NativePreparationID)
	options.NativePreparationID = ""
	return proof.deadline, found && graphBound && time.Now().Before(proof.deadline) && reflect.DeepEqual(options, proof.options) && reflect.DeepEqual(checked.fallback, proof.fallback)
}

// The current runtime graph is checked before Box construction. Holding the
// same token while replacing a referenced leaf/selector cannot bypass prepare.
func BindPreparations(ctx context.Context, options option.Options) (context.Context, error) {
	checked := make(map[string]preparedScope)
	for _, outbound := range options.Outbounds {
		if outbound.Type != Type {
			continue
		}
		tg, ok := outbound.Options.(*option.PokrovTelegramWSOutboundOptions)
		if !ok || outbound.Tag != "pokrov-telegram-ws-"+tg.ServiceID {
			return nil, errScope
		}
		graph, err := FallbackDefinitions(options, tg.VPNOutbound)
		if err != nil {
			return nil, err
		}
		preparations.Lock()
		proof, found := preparations.values[tg.NativePreparationID]
		copyOptions := *tg
		copyOptions.NativePreparationID = ""
		valid := found && time.Now().Before(proof.deadline) && reflect.DeepEqual(copyOptions, proof.options) && reflect.DeepEqual(graph, proof.fallback)
		if valid {
			checked[tg.NativePreparationID] = proof
		}
		preparations.Unlock()
		if !valid {
			return nil, errScope
		}
	}
	if len(checked) == 0 {
		return ctx, nil
	}
	return context.WithValue(ctx, preparationContextKey{}, checked), nil
}

func FallbackDefinitions(options option.Options, tag string) (map[string]string, error) {
	type definition struct {
		kind    string
		options any
	}
	byTag := make(map[string]definition, len(options.Outbounds)+len(options.Endpoints))
	for _, outbound := range options.Outbounds {
		if outbound.Tag == "" || byTag[outbound.Tag].kind != "" {
			return nil, errScope
		}
		byTag[outbound.Tag] = definition{outbound.Type, outbound.Options}
	}
	for _, endpoint := range options.Endpoints {
		if endpoint.Tag == "" || byTag[endpoint.Tag].kind != "" {
			return nil, errScope
		}
		byTag[endpoint.Tag] = definition{endpoint.Type, endpoint.Options}
	}
	definitions := make(map[string]string)
	visiting := make(map[string]bool)
	var visit func(string) error
	visit = func(name string) error {
		if visiting[name] {
			return errScope
		}
		if _, done := definitions[name]; done {
			return nil
		}
		outbound, found := byTag[name]
		if !found {
			return errScope
		}
		visiting[name] = true
		defer delete(visiting, name)
		var children []string
		var detour string
		switch value := outbound.options.(type) {
		case *option.VLESSOutboundOptions:
			if value.TLS == nil || !value.TLS.Enabled || value.TLS.Insecure {
				return errScope
			}
			detour = value.Detour
		case *option.Hysteria2OutboundOptions:
			detour = value.Detour
		case *option.LegacyWireGuardOutboundOptions:
			detour = value.Detour
		case *option.WireGuardEndpointOptions:
			detour = value.Detour
		case *option.AwgEndpointOptions:
			detour = value.Detour
		case *option.SelectorOutboundOptions:
			children = value.Outbounds
		case *option.URLTestOutboundOptions:
			children = value.Outbounds
		default:
			return errScope
		}
		if detour != "" {
			return errScope
		}
		if (outbound.kind == "selector" || outbound.kind == "urltest") && len(children) == 0 {
			return errScope
		}
		for _, child := range children {
			if err := visit(child); err != nil {
				return err
			}
		}
		encoded, err := json.Marshal(outbound.options)
		if err != nil {
			return errScope
		}
		definitions[name] = outbound.kind + "\n" + string(encoded)
		return nil
	}
	if err := visit(tag); err != nil {
		return nil, err
	}
	return definitions, nil
}

func (h *Outbound) AdmissionID() string { return h.admissionID }
func (h *Outbound) ServiceID() string   { return h.serviceID }

func (h *Outbound) currentLocked() bool {
	now := time.Now()
	return !h.closed && !h.withdrawn && !now.Before(h.issued) && now.Before(h.expires) && now.Before(h.deadline)
}

func (h *Outbound) IsReady() bool {
	h.mu.Lock()
	current := h.currentLocked()
	var cleanup func()
	if !current {
		cleanup = h.denyLocked()
	}
	ready := current && h.admitted
	h.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
	return ready
}

func (h *Outbound) AdmitAdmission(expectedID string) bool {
	h.mu.Lock()
	if expectedID != h.admissionID || h.admitted {
		h.mu.Unlock()
		return false
	}
	if !h.currentLocked() {
		cleanup := h.denyLocked()
		h.mu.Unlock()
		if cleanup != nil {
			cleanup()
		}
		return false
	}
	h.admitted = true
	h.mu.Unlock()
	return true
}

func (h *Outbound) denyLocked() func() {
	if h.withdrawn {
		return nil
	}
	h.withdrawn, h.admitted = true, false
	flows := make([]*telegramFlow, 0, len(h.flows))
	for flow := range h.flows {
		flows = append(flows, flow)
	}
	if h.expiryTimer != nil {
		h.expiryTimer.Stop()
	}
	return func() {
		h.withdrawCancel()
		for _, flow := range flows {
			flow.withdraw()
		}
	}
}

// Deny first. Pending reads/setup retain their original bytes for one live-parent
// VPN fallback; streams handed to WSS close and are never replayed.
func (h *Outbound) WithdrawAdmission(expectedID string) bool {
	h.mu.Lock()
	if expectedID != h.admissionID {
		h.mu.Unlock()
		return false
	}
	cleanup := h.denyLocked()
	h.mu.Unlock()
	if cleanup == nil {
		return false
	}
	cleanup()
	return true
}

func (h *Outbound) InterfaceUpdated(_ context.Context) {
	h.WithdrawAdmission(h.admissionID)
}

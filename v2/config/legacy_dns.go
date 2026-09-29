package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	SJ "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

type legacyDNSServer struct {
	Type                 string                `json:"type,omitempty"`
	Tag                  string                `json:"tag,omitempty"`
	Address              string                `json:"address"`
	AddressResolver      string                `json:"address_resolver,omitempty"`
	AddressStrategy      option.DomainStrategy `json:"address_strategy,omitempty"`
	AddressFallbackDelay badoption.Duration    `json:"address_fallback_delay,omitempty"`
	Strategy             option.DomainStrategy `json:"strategy,omitempty"`
	Detour               string                `json:"detour,omitempty"`
	ClientSubnet         *badoption.Prefixable `json:"client_subnet,omitempty"`
}

// NormalizeLegacyDNS migrates imported DNS servers/outbounds before the strict
// 1.14 decode and removes Portal's known non-runtime metadata extension.
// It never changes the stored profile and leaves already typed input untouched.
func NormalizeLegacyDNS(content []byte) ([]byte, error) {
	var root map[string]json.RawMessage
	decoder := json.NewDecoder(SJ.NewCommentFilter(bytes.NewReader(content)))
	if err := decoder.Decode(&root); err != nil || root == nil {
		return nil, fmt.Errorf("invalid configuration JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("invalid configuration JSON")
	}
	_, changed := root["_meta"]
	delete(root, "_meta")
	outboundsChanged, err := migrateLegacyDNSOutbound(root)
	if err != nil {
		return nil, err
	}
	changed = changed || outboundsChanged
	var dns map[string]json.RawMessage
	if len(root["dns"]) == 0 || bytes.Equal(root["dns"], []byte("null")) {
		if changed {
			return json.Marshal(root)
		}
		return content, nil
	}
	if err := json.Unmarshal(root["dns"], &dns); err != nil || dns == nil {
		return nil, fmt.Errorf("invalid DNS configuration")
	}
	var servers []json.RawMessage
	if err := json.Unmarshal(dns["servers"], &servers); len(dns["servers"]) != 0 && err != nil {
		return nil, fmt.Errorf("invalid DNS servers")
	}
	var defaultOutbound string
	var route struct {
		Final string `json:"final"`
	}
	if err := json.Unmarshal(root["route"], &route); len(root["route"]) != 0 && err != nil {
		return nil, fmt.Errorf("invalid route configuration")
	}
	defaultOutbound = route.Final
	if defaultOutbound == "" {
		var outbounds []struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(root["outbounds"], &outbounds); len(root["outbounds"]) != 0 && err != nil {
			return nil, fmt.Errorf("invalid outbounds")
		}
		if len(outbounds) > 0 {
			defaultOutbound = outbounds[0].Tag
			if defaultOutbound == "" {
				defaultOutbound = "0" // Box assigns the index to an untagged outbound.
			}
		}
	}
	for i, encoded := range servers {
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(encoded, &header); err != nil {
			return nil, fmt.Errorf("invalid DNS server at index %d", i)
		}
		if header.Type != "" && header.Type != C.DNSTypeLegacy {
			continue
		}
		var legacy legacyDNSServer
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&legacy); err != nil || legacy.Address == "" {
			return nil, fmt.Errorf("invalid legacy DNS server at index %d", i)
		}
		// Portal uses global/rule query options. Legacy per-server overrides cannot
		// be moved there without changing explicit resolver/rule precedence.
		if legacy.Strategy != 0 || legacy.ClientSubnet != nil {
			return nil, fmt.Errorf("unsupported legacy DNS query overrides at index %d", i)
		}
		server, err := migrateLegacyDNSServer(legacy, defaultOutbound)
		if err != nil {
			return nil, fmt.Errorf("unsupported legacy DNS server at index %d", i)
		}
		servers[i], err = server.MarshalJSONContext(context.Background())
		if err != nil {
			return nil, fmt.Errorf("cannot encode DNS server at index %d", i)
		}
		changed = true
	}
	if !changed {
		return content, nil
	}
	dns["servers"], _ = json.Marshal(servers)
	root["dns"], _ = json.Marshal(dns)
	return json.Marshal(root)
}

func migrateLegacyDNSServer(legacy legacyDNSServer, defaultOutbound string) (*option.DNSServerOptions, error) {
	if strings.ContainsAny(legacy.Address, " \t\r\n") {
		return nil, fmt.Errorf("invalid DNS address")
	}
	if strings.Contains(legacy.Address, "://") {
		address, err := url.Parse(legacy.Address)
		if err != nil || address.User != nil || address.RawQuery != "" || address.Fragment != "" || address.Hostname() == "" {
			return nil, fmt.Errorf("invalid DNS URL")
		}
		if port := address.Port(); port != "" {
			if value, err := strconv.ParseUint(port, 10, 16); err != nil || value == 0 {
				return nil, fmt.Errorf("invalid DNS port")
			}
		}
		if address.Scheme != C.DNSTypeHTTPS && address.Scheme != C.DNSTypeHTTP3 && address.Path != "" {
			return nil, fmt.Errorf("unsupported DNS URL path")
		}
	}
	server, err := getDNSServerOptions(legacy.Tag, legacy.Address, legacy.AddressResolver, legacy.Detour)
	if err != nil {
		return nil, err
	}
	switch server.Type {
	case C.DNSTypeLocal, C.DNSTypeUDP, C.DNSTypeTCP, C.DNSTypeTLS, C.DNSTypeQUIC, C.DNSTypeHTTPS, C.DNSTypeHTTP3:
	default:
		return nil, fmt.Errorf("unsupported legacy DNS transport")
	}
	// The generator's prefer_go, timeout and resolver defaults are not legacy defaults.
	if local, ok := server.Options.(*option.LocalDNSServerOptions); ok {
		local.PreferGo = false
	}
	dialer := option.DialerOptions{Detour: legacy.Detour}
	if dialer.Detour == "" {
		dialer.Detour = defaultOutbound
	}
	dialer.FallbackDelay = legacy.AddressFallbackDelay
	if legacy.AddressResolver != "" {
		dialer.DomainResolver = &option.DomainResolveOptions{Server: legacy.AddressResolver, Strategy: legacy.AddressStrategy}
	} else if legacy.AddressStrategy != 0 {
		return nil, fmt.Errorf("address strategy requires resolver")
	}
	server.Options.(option.DialerOptionsWrapper).ReplaceDialerOptions(dialer)
	return server, nil
}

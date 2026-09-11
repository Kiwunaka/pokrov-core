// Package linuxruntime owns the materialized-profile boundary for linuxd.
// It does not accept executable paths or let a profile choose host networking.
package linuxruntime

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

const (
	Protocol                  = "pokrov-linux-core-v1"
	MaximumConfigBytes        = 512 * 1024
	TunnelInterface           = "pokrov0"
	RoutingMark        uint32 = 0x504b
)

var ErrProfile = errors.New("linux profile rejected")

// Plan contains only the network values linuxd needs. Config never enters IPC.
type Plan struct {
	TunnelInterface string   `json:"tunnel_interface"`
	RoutingMark     uint32   `json:"routing_mark"`
	DNSServers      []string `json:"dns_servers"`
}

// Prepare removes profile control over TUN, route ownership, log files and
// auxiliary services before the embedded engine parses the resulting JSON.
func Prepare(input []byte) ([]byte, Plan, error) {
	if len(input) == 0 || len(input) > MaximumConfigBytes {
		return nil, Plan{}, ErrProfile
	}
	var root map[string]any
	if json.Unmarshal(input, &root) != nil || root == nil {
		return nil, Plan{}, ErrProfile
	}
	for key := range root {
		switch key {
		case "log", "dns", "inbounds", "outbounds", "route":
		default:
			return nil, Plan{}, ErrProfile
		}
	}
	root["log"] = map[string]any{"disabled": true}
	// Reject filesystem and namespace access even in nested TLS/DNS/rule options.
	if !safeValues(root, false) {
		return nil, Plan{}, ErrProfile
	}
	dns, ok := root["dns"].(map[string]any)
	if !ok || len(dns) == 0 {
		return nil, Plan{}, ErrProfile
	}
	outbounds, ok := root["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		return nil, Plan{}, ErrProfile
	}
	for _, value := range outbounds {
		outbound, ok := value.(map[string]any)
		if !ok {
			return nil, Plan{}, ErrProfile
		}
		switch outbound["type"] {
		case "direct", "block", "dns", "selector", "urltest", "vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic", "socks", "http", "wireguard", "anytls":
		default:
			return nil, Plan{}, ErrProfile
		}
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return nil, Plan{}, ErrProfile
	}
	var tunnel map[string]any
	for _, value := range inbounds {
		inbound, ok := value.(map[string]any)
		if !ok {
			return nil, Plan{}, ErrProfile
		}
		switch inbound["type"] {
		case "tun":
			if tunnel != nil || !onlyKeys(inbound, "type", "tag", "mtu", "auto_route", "strict_route", "stack", "address", "domain_strategy") {
				return nil, Plan{}, ErrProfile
			}
			tunnel = inbound
		case "mixed":
			if !onlyKeys(inbound, "type", "tag", "listen", "listen_port", "domain_strategy") {
				return nil, Plan{}, ErrProfile
			}
			address, ok := inbound["listen"].(string)
			ip, err := netip.ParseAddr(address)
			port, validPort := inbound["listen_port"].(float64)
			if !ok || err != nil || !ip.IsLoopback() || !validPort || port < 1024 || port > 65535 || port != float64(uint16(port)) {
				return nil, Plan{}, ErrProfile
			}
		default:
			return nil, Plan{}, ErrProfile
		}
	}
	if tunnel == nil {
		return nil, Plan{}, ErrProfile
	}
	addresses, ok := tunnel["address"].([]any)
	if !ok || len(addresses) == 0 || len(addresses) > 2 {
		return nil, Plan{}, ErrProfile
	}
	plan := Plan{TunnelInterface: TunnelInterface, RoutingMark: RoutingMark}
	seen := map[string]bool{}
	for _, value := range addresses {
		address, ok := value.(string)
		if !ok || seen[address] {
			return nil, Plan{}, ErrProfile
		}
		seen[address] = true
		switch address {
		case "172.19.0.1/28":
			plan.DNSServers = append(plan.DNSServers, "172.19.0.2")
		case "fdfe:dcba:9876::1/126":
			plan.DNSServers = append(plan.DNSServers, "fdfe:dcba:9876::2")
		default:
			return nil, Plan{}, ErrProfile
		}
	}
	mtu, ok := tunnel["mtu"].(float64)
	if !ok || mtu < 1280 || mtu > 1500 || mtu != float64(uint32(mtu)) {
		return nil, Plan{}, ErrProfile
	}
	tunnel["interface_name"] = TunnelInterface
	// linuxd journals and owns policy routes; Core owns only the TUN device.
	tunnel["auto_route"] = false
	tunnel["strict_route"] = true
	tunnel["auto_redirect"] = false // linuxd exclusively owns nftables.
	tunnel["stack"] = "system"
	route, ok := root["route"].(map[string]any)
	if !ok || !onlyKeys(route, "rules", "rule_set", "final", "find_process", "auto_detect_interface", "default_domain_resolver") {
		return nil, Plan{}, ErrProfile
	}
	route["auto_detect_interface"] = true
	route["default_mark"] = RoutingMark
	rules, ok := route["rules"].([]any)
	if !ok {
		return nil, Plan{}, ErrProfile
	}
	// resolved sends only into the owned TUN; Core retains the profile's DNS
	// transport and resolver policy instead of emitting plaintext uplink DNS.
	route["rules"] = append([]any{map[string]any{"port": 53, "action": "hijack-dns"}}, rules...)
	root["log"] = map[string]any{"disabled": true}
	output, err := json.Marshal(root)
	if err != nil {
		return nil, Plan{}, ErrProfile
	}
	return output, plan, nil
}

func onlyKeys(value map[string]any, allowed ...string) bool {
	for key := range value {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func safeValues(value any, transport bool) bool {
	switch item := value.(type) {
	case map[string]any:
		uriPath := transport || item["type"] == "https" || item["type"] == "http"
		for key, child := range item {
			lower := strings.ToLower(key)
			if strings.HasSuffix(lower, "_path") || strings.HasSuffix(lower, "_directory") ||
				lower == "netns" || lower == "system_interface" || lower == "interface_name" ||
				lower == "routing_mark" || lower == "default_mark" || lower == "bind_interface" ||
				lower == "output" || (lower == "path" && !uriPath) {
				return false
			}
			isTransport := key == "transport"
			if isTransport {
				options, ok := child.(map[string]any)
				if !ok {
					return false
				}
				switch options["type"] {
				case "http", "ws", "quic", "grpc", "httpupgrade":
				default:
					return false
				}
			}
			if !safeValues(child, isTransport) {
				return false
			}
		}
	case []any:
		for _, child := range item {
			if !safeValues(child, transport) {
				return false
			}
		}
	}
	return true
}

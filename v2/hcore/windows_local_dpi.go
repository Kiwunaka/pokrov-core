package hcore

import (
	"encoding/json"
	"errors"
	"runtime"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/daemon"
)

// Core support is separate from Android's SOCKS admission API and from a host's
// installed packet-filter executor. Preparation never starts or admits a child.
func WindowsLocalDpiAdmissionVersion() int {
	if runtime.GOOS == "windows" {
		return 1
	}
	return 0
}

type windowsDpiMetadata struct {
	Mode             string            `json:"mode"`
	Platform         string            `json:"platform"`
	Envelope         string            `json:"catalog_envelope"`
	Digest           string            `json:"catalog_sha256"`
	Revision         int64             `json:"revision"`
	SecurityRevision int64             `json:"security_revision"`
	AccessState      string            `json:"access_state"`
	Services         map[string]string `json:"services"`
}

type windowsDpiDomain struct {
	Name   string `json:"name"`
	Match  string `json:"match"`
	Shared bool   `json:"shared"`
}

type windowsDpiService struct {
	ServiceID   string             `json:"service_id"`
	OutboundTag string             `json:"outbound_tag"`
	ControlHost string             `json:"control_host"`
	Domains     []windowsDpiDomain `json:"domains"`
}

type windowsDpiPreparation struct {
	Profile   json.RawMessage     `json:"profile"`
	ExpiresAt string              `json:"expires_at"`
	Services  []windowsDpiService `json:"services"`
}

var errWindowsDpiScope = errors.New("windows_local_dpi_scope_invalid")

// publicKeysJSON and audience belong to the native host's compiled pins, never
// IPC metadata. The returned JSON is private caller-owned runtime material.
// A host must bind its fresh TLS/HEAD proof and child lifetime to the resulting
// runtime's captured admission IDs before using AdmitLocalDpiAdmission.
func PrepareWindowsLocalDpiProfile(configJSON, publicKeysJSON, audience, bindInterface string) (string, error) {
	if WindowsLocalDpiAdmissionVersion() != 1 || bindInterface == "" || strings.ContainsRune(bindInterface, 0) {
		return "", errWindowsDpiScope
	}
	var config map[string]json.RawMessage
	var hostMeta map[string]json.RawMessage
	var metadata windowsDpiMetadata
	if json.Unmarshal([]byte(configJSON), &config) != nil || config == nil ||
		json.Unmarshal(config["_meta"], &hostMeta) != nil ||
		json.Unmarshal(hostMeta["local_dpi"], &metadata) != nil ||
		metadata.Mode != "selective" || metadata.Platform != "windows" || len(metadata.Services) == 0 || len(metadata.Services) > 256 {
		return "", errWindowsDpiScope
	}
	var envelope struct {
		Payload struct {
			IssuedAt  string `json:"issued_at"`
			ExpiresAt string `json:"expires_at"`
			Services  []struct {
				ServiceID string             `json:"service_id"`
				Domains   []windowsDpiDomain `json:"domains"`
			} `json:"services"`
		} `json:"payload"`
	}
	var outbounds []map[string]json.RawMessage
	var endpoints []json.RawMessage
	var route map[string]json.RawMessage
	var rules []map[string]json.RawMessage
	if json.Unmarshal([]byte(metadata.Envelope), &envelope) != nil ||
		json.Unmarshal(config["outbounds"], &outbounds) != nil ||
		json.Unmarshal(config["route"], &route) != nil || route == nil ||
		json.Unmarshal(route["rules"], &rules) != nil {
		return "", errWindowsDpiScope
	}
	if raw, present := config["endpoints"]; present && (json.Unmarshal(raw, &endpoints) != nil || len(endpoints) != 0) {
		return "", errWindowsDpiScope
	}
	byTag := make(map[string]map[string]json.RawMessage, len(outbounds))
	for _, outbound := range outbounds {
		tag := windowsDpiString(outbound["tag"])
		if tag == "" || byTag[tag] != nil {
			return "", errWindowsDpiScope
		}
		byTag[tag] = outbound
	}
	final := byTag[windowsDpiString(route["final"])]
	if windowsDpiString(final["type"]) != "direct" || windowsDpiString(final["detour"]) != "" {
		return "", errWindowsDpiScope
	}
	serviceIDs := make([]string, 0, len(metadata.Services))
	for serviceID := range metadata.Services {
		serviceIDs = append(serviceIDs, serviceID)
	}
	sort.Strings(serviceIDs)
	prepared := windowsDpiPreparation{ExpiresAt: envelope.Payload.ExpiresAt}
	for _, serviceID := range serviceIDs {
		host := metadata.Services[serviceID]
		if !daemon.VerifyWindowsLocalDpiCatalog(metadata.Envelope, publicKeysJSON, audience, metadata.Digest,
			metadata.Revision, metadata.SecurityRevision, serviceID, host, metadata.AccessState) {
			return "", errWindowsDpiScope
		}
		var domains []windowsDpiDomain
		for _, signed := range envelope.Payload.Services {
			if signed.ServiceID == serviceID {
				domains = signed.Domains
				break
			}
		}
		tag := "pokrov-local-dpi-" + serviceID
		if byTag[tag] != nil {
			return "", errWindowsDpiScope
		}
		selected := windowsDpiService{ServiceID: serviceID, OutboundTag: tag, ControlHost: host}
		var fallback string
		var matching []map[string]json.RawMessage
		for _, rule := range rules {
			var window map[string]json.RawMessage
			if json.Unmarshal(rule["pokrov_catalog_window"], &window) != nil ||
				windowsDpiString(window["service_id"]) != serviceID || windowsDpiString(rule["action"]) != "route" ||
				windowsDpiString(window["issued_at"]) != envelope.Payload.IssuedAt ||
				windowsDpiString(window["expires_at"]) != envelope.Payload.ExpiresAt {
				continue
			}
			if _, leased := window["lease_id"]; leased {
				continue
			}
			if _, leasedGroup := window["lease_group"]; leasedGroup {
				continue
			}
			var inverted bool
			if raw, present := rule["invert"]; present && (json.Unmarshal(raw, &inverted) != nil || inverted) {
				continue
			}
			// Address selectors and merged rule sets can satisfy the same OR group
			// as exact/suffix domains, outside the signed service scope.
			if rule["domain_regex"] != nil || rule["domain_keyword"] != nil ||
				rule["ip_cidr"] != nil || rule["ip_is_private"] != nil || rule["rule_set"] != nil {
				continue
			}
			for _, domain := range domains {
				key := "domain"
				other := "domain_suffix"
				if domain.Match == "suffix" {
					key, other = other, key
				}
				var names []string
				if domain.Shared || rule[other] != nil || json.Unmarshal(rule[key], &names) != nil || len(names) != 1 || names[0] != domain.Name {
					continue
				}
				vpn := windowsDpiString(rule["outbound"])
				if !windowsDpiProtectedVPN(byTag, vpn, make(map[string]bool)) || (fallback != "" && fallback != vpn) {
					return "", errWindowsDpiScope
				}
				fallback = vpn
				matching = append(matching, rule)
				selected.Domains = append(selected.Domains, domain)
			}
		}
		if len(matching) == 0 {
			continue
		}
		controlInScope := false
		for _, domain := range selected.Domains {
			controlInScope = controlInScope || domain.Name == host && domain.Match == "exact"
		}
		if !controlInScope {
			return "", errWindowsDpiScope
		}
		encoded, _ := json.Marshal(map[string]any{"type": "pokrov-local-dpi", "tag": tag, "windows_direct": true,
			"bind_interface": bindInterface, "vpn_outbound": fallback, "service_id": serviceID})
		var local map[string]json.RawMessage
		_ = json.Unmarshal(encoded, &local)
		outbounds = append(outbounds, local)
		for _, rule := range matching {
			rule["outbound"], _ = json.Marshal(tag)
		}
		prepared.Services = append(prepared.Services, selected)
	}
	if len(prepared.Services) == 0 {
		return "", errWindowsDpiScope
	}
	config["outbounds"], _ = json.Marshal(outbounds)
	route["rules"], _ = json.Marshal(rules)
	config["route"], _ = json.Marshal(route)
	delete(config, "_meta")
	prepared.Profile, _ = json.Marshal(config)
	encoded, err := json.Marshal(prepared)
	return string(encoded), err
}

func windowsDpiString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func windowsDpiProtectedVPN(byTag map[string]map[string]json.RawMessage, tag string, visiting map[string]bool) bool {
	outbound := byTag[tag]
	if outbound == nil || visiting[tag] || windowsDpiString(outbound["detour"]) != "" {
		return false
	}
	visiting[tag] = true
	defer delete(visiting, tag)
	switch windowsDpiString(outbound["type"]) {
	case "vless":
		var tls struct {
			Enabled  bool `json:"enabled"`
			Insecure bool `json:"insecure"`
		}
		return json.Unmarshal(outbound["tls"], &tls) == nil && tls.Enabled && !tls.Insecure
	case "hysteria2", "wireguard", "awg":
		return true
	case "selector", "urltest":
		var children []string
		if json.Unmarshal(outbound["outbounds"], &children) != nil || len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !windowsDpiProtectedVPN(byTag, child, visiting) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

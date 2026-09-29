package config

import (
	"encoding/json"
	"fmt"
	"strconv"
)

func migrateLegacyDNSOutbound(root map[string]json.RawMessage) (bool, error) {
	var outbounds []json.RawMessage
	if err := json.Unmarshal(root["outbounds"], &outbounds); len(root["outbounds"]) != 0 && err != nil {
		return false, fmt.Errorf("invalid outbounds")
	}
	dnsTags := make(map[string]bool)
	defaultIsDNS := false
	retained := make([]json.RawMessage, 0, len(outbounds))
	for i, encoded := range outbounds {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			return false, fmt.Errorf("invalid outbound at index %d", i)
		}
		var kind, tag string
		if err := json.Unmarshal(fields["type"], &kind); err != nil {
			return false, fmt.Errorf("invalid outbound type at index %d", i)
		}
		if err := json.Unmarshal(fields["tag"], &tag); len(fields["tag"]) != 0 && err != nil {
			return false, fmt.Errorf("invalid outbound tag at index %d", i)
		}
		if kind != "dns" {
			retained = append(retained, encoded)
			continue
		}
		for key := range fields {
			if key != "type" && key != "tag" {
				return false, fmt.Errorf("unsupported legacy DNS outbound options")
			}
		}
		if tag == "" {
			tag = strconv.Itoa(i)
		}
		if dnsTags[tag] {
			return false, fmt.Errorf("duplicate legacy DNS outbound")
		}
		dnsTags[tag] = true
		defaultIsDNS = defaultIsDNS || i == 0
	}
	if len(dnsTags) == 0 {
		return false, nil
	}
	// Removing an outbound must not renumber implicit tags or conceal duplicates.
	for _, encoded := range retained {
		var header struct {
			Tag string `json:"tag"`
		}
		if json.Unmarshal(encoded, &header) != nil || header.Tag == "" || dnsTags[header.Tag] {
			return false, fmt.Errorf("ambiguous legacy DNS outbound tags")
		}
	}
	var endpoints []struct {
		Tag string `json:"tag"`
	}
	if err := json.Unmarshal(root["endpoints"], &endpoints); len(root["endpoints"]) != 0 && err != nil {
		return false, fmt.Errorf("invalid endpoints")
	}
	for i, endpoint := range endpoints {
		tag := endpoint.Tag
		if tag == "" {
			tag = strconv.Itoa(i)
		}
		if dnsTags[tag] {
			return false, fmt.Errorf("duplicate legacy DNS outbound and endpoint tag")
		}
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(root["route"], &route); len(root["route"]) != 0 && err != nil {
		return false, fmt.Errorf("invalid route configuration")
	}
	var final string
	_ = json.Unmarshal(route["final"], &final)
	if dnsTags[final] || final == "" && defaultIsDNS {
		return false, fmt.Errorf("legacy DNS outbound cannot be route final")
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(route["rules"], &rules); len(route["rules"]) != 0 && err != nil {
		return false, fmt.Errorf("invalid route rules")
	}
	for _, rule := range rules {
		var target, action string
		_ = json.Unmarshal(rule["outbound"], &target)
		if !dnsTags[target] {
			continue
		}
		if err := json.Unmarshal(rule["action"], &action); len(rule["action"]) != 0 && err != nil {
			return false, fmt.Errorf("invalid legacy DNS route action")
		}
		if action != "" && action != "route" {
			return false, fmt.Errorf("unsupported legacy DNS route action")
		}
		delete(rule, "outbound")
		rule["action"] = json.RawMessage(`"hijack-dns"`)
	}
	if len(route["rules"]) != 0 {
		route["rules"], _ = json.Marshal(rules)
		root["route"], _ = json.Marshal(route)
	}
	root["outbounds"], _ = json.Marshal(retained)
	for _, key := range []string{"outbounds", "endpoints", "inbounds", "dns", "route", "services", "http_clients"} {
		var value any
		_ = json.Unmarshal(root[key], &value)
		if referencesLegacyDNSOutbound(value, dnsTags) {
			return false, fmt.Errorf("unsupported reference to legacy DNS outbound")
		}
	}
	return true, nil
}

func referencesLegacyDNSOutbound(value any, tags map[string]bool) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			switch key {
			case "outbound", "detour", "download_detour", "default":
				if tag, ok := child.(string); ok && tags[tag] {
					return true
				}
			case "outbounds":
				if children, ok := child.([]any); ok {
					for _, tag := range children {
						if tag, ok := tag.(string); ok && tags[tag] {
							return true
						}
					}
				}
			}
			if referencesLegacyDNSOutbound(child, tags) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if referencesLegacyDNSOutbound(child, tags) {
				return true
			}
		}
	}
	return false
}

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/pokrov/telegramws"
)

var errTelegramScope = errors.New("telegram_ws_scope_invalid")

type telegramMetadata struct {
	SchemaVersion    int               `json:"schema_version"`
	Mode             string            `json:"mode"`
	Platform         string            `json:"platform"`
	Envelope         string            `json:"catalog_envelope"`
	Digest           string            `json:"catalog_sha256"`
	Revision         int64             `json:"revision"`
	SecurityRevision int64             `json:"security_revision"`
	AccessState      string            `json:"access_state"`
	Services         map[string]string `json:"services"`
}

type telegramPreparedService struct {
	ServiceID   string `json:"service_id"`
	OutboundTag string `json:"outbound_tag"`
}

type telegramPreparation struct {
	SchemaVersion int                       `json:"schema_version"`
	Profile       json.RawMessage           `json:"profile"`
	IssuedAt      string                    `json:"issued_at"`
	ExpiresAt     string                    `json:"expires_at"`
	Services      []telegramPreparedService `json:"services"`
}

func catalogNativeRouteIntent(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	for _, extras := range [][]string{nil, {"local_dpi_control_host"}, {"telegram_ws_datacenters"}, {"local_dpi_control_host", "telegram_ws_datacenters"}} {
		keys := append([]string{"mode", "action"}, extras...)
		if intent, valid := smartAccessControlObject(raw, keys...); valid {
			return intent, true
		}
	}
	return nil, false
}

func telegramCatalogDatacenters(raw json.RawMessage) []option.PokrovTelegramWSDatacenter {
	rows, valid := localDpiCatalogArray(raw, 1, 5)
	if !valid {
		return nil
	}
	seenIDs, seenAddresses := make(map[int]bool), make(map[string]bool)
	var result []option.PokrovTelegramWSDatacenter
	for _, raw := range rows {
		row, valid := smartAccessControlObject(raw, "id", "addresses", "websocket_address")
		var dc option.PokrovTelegramWSDatacenter
		if !valid || json.Unmarshal(row["id"], &dc.ID) != nil || dc.ID < 1 || dc.ID > 5 || seenIDs[dc.ID] {
			return nil
		}
		seenIDs[dc.ID] = true
		dc.WebsocketAddress, valid = localDpiCatalogString(row["websocket_address"])
		if !valid || !telegramws.PublicDatacenterAddress(dc.WebsocketAddress) {
			return nil
		}
		addresses, valid := localDpiCatalogArray(row["addresses"], 1, 16)
		if !valid {
			return nil
		}
		for _, raw := range addresses {
			address, valid := localDpiCatalogString(raw)
			if !valid || !telegramws.PublicDatacenterAddress(address) || seenAddresses[address] {
				return nil
			}
			seenAddresses[address] = true
			dc.Addresses = append(dc.Addresses, address)
		}
		sort.Strings(dc.Addresses)
		result = append(result, dc)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func telegramServiceDatacenters(service map[string]json.RawMessage, accessState, platform string) []option.PokrovTelegramWSDatacenter {
	status, _ := localDpiCatalogString(service["evidence_status"])
	if string(service["enabled"]) != "true" || status != "verified" || !localDpiCatalogContains(service["platforms"], platform) || !localDpiCatalogContains(service["access_states"], accessState) {
		return nil
	}
	intents, valid := localDpiCatalogArray(service["route_intents"], 1, 5)
	if !valid {
		return nil
	}
	seen := make(map[string]bool)
	var result []option.PokrovTelegramWSDatacenter
	for _, raw := range intents {
		intent, valid := catalogNativeRouteIntent(raw)
		mode, _ := localDpiCatalogString(intent["mode"])
		action, _ := localDpiCatalogString(intent["action"])
		if !valid || mode == "" || seen[mode] {
			return nil
		}
		seen[mode] = true
		if raw, present := intent["telegram_ws_datacenters"]; present {
			if mode != "selective" || action != "vpn" {
				return nil
			}
			result = telegramCatalogDatacenters(raw)
			if result == nil {
				return nil
			}
		}
	}
	return result
}

// Native wrappers fix platform; pins, audience and the captured physical
// interface are supplied by the trusted host, never private IPC metadata.
func PrepareTelegramWSProfile(configJSON, publicKeysJSON, audience, bindInterface, platform string) (string, error) {
	if (platform != "windows" && platform != "android") || bindInterface == "" || strings.ContainsRune(bindInterface, 0) {
		return "", errTelegramScope
	}
	var config, hostMeta map[string]json.RawMessage
	var metadata telegramMetadata
	if json.Unmarshal([]byte(configJSON), &config) != nil || config == nil || json.Unmarshal(config["_meta"], &hostMeta) != nil {
		return "", errTelegramScope
	}
	if _, valid := smartAccessControlObject(hostMeta["telegram_ws"], "schema_version", "mode", "platform", "catalog_envelope", "catalog_sha256", "revision", "security_revision", "access_state", "services"); !valid {
		return "", errTelegramScope
	}
	if json.Unmarshal(hostMeta["telegram_ws"], &metadata) != nil || metadata.SchemaVersion != 1 || metadata.Mode != "selective" || metadata.Platform != platform || len(metadata.Services) == 0 || len(metadata.Services) > 256 {
		return "", errTelegramScope
	}
	var serviceKeys []string
	for key := range metadata.Services {
		serviceKeys = append(serviceKeys, key)
	}
	var strictMeta map[string]json.RawMessage
	_ = json.Unmarshal(hostMeta["telegram_ws"], &strictMeta)
	if _, valid := smartAccessControlObject(strictMeta["services"], serviceKeys...); !valid {
		return "", errTelegramScope
	}
	if raw, present := hostMeta["local_dpi"]; present {
		var other telegramMetadata
		if json.Unmarshal(raw, &other) != nil || other.Envelope != metadata.Envelope || other.Digest != metadata.Digest || other.Revision != metadata.Revision || other.SecurityRevision != metadata.SecurityRevision || other.AccessState != metadata.AccessState {
			return "", errTelegramScope
		}
	}
	var outbounds []map[string]json.RawMessage
	var route map[string]json.RawMessage
	var rules []map[string]json.RawMessage
	if json.Unmarshal(config["outbounds"], &outbounds) != nil || json.Unmarshal(config["route"], &route) != nil || json.Unmarshal(route["rules"], &rules) != nil {
		return "", errTelegramScope
	}
	for _, row := range outbounds {
		kind, _ := localDpiCatalogString(row["type"])
		if kind == telegramws.Type || row["native_preparation_id"] != nil {
			return "", errTelegramScope
		}
	}
	// Parse only the runtime copy for exact typed fallback-definition binding.
	delete(config, "_meta")
	runtimeBytes, _ := json.Marshal(config)
	parsed, err := parseConfig(include.Context(context.Background()), string(runtimeBytes))
	config["_meta"], _ = json.Marshal(hostMeta)
	if err != nil {
		return "", errTelegramScope
	}
	sort.Strings(serviceKeys)
	prepared := telegramPreparation{SchemaVersion: 1}
	var telegramRules []map[string]json.RawMessage
	usedAddresses := make(map[string]bool)
	for _, serviceID := range serviceKeys {
		verified := verifiedRoutingCatalogService(metadata.Envelope, publicKeysJSON, audience, metadata.Digest, metadata.Revision, metadata.SecurityRevision, serviceID, metadata.AccessState, time.Now())
		if verified == nil {
			return "", errTelegramScope
		}
		datacenters := telegramServiceDatacenters(verified.service, metadata.AccessState, platform)
		if datacenters == nil {
			return "", errTelegramScope
		}
		vpnTag := metadata.Services[serviceID]
		fallback, err := telegramws.FallbackDefinitions(parsed, vpnTag)
		if err != nil || !telegramHasServiceVPNRule(rules, verified, serviceID, vpnTag) {
			return "", errTelegramScope
		}
		tag := "pokrov-telegram-ws-" + serviceID
		for _, row := range outbounds {
			if name, _ := localDpiCatalogString(row["tag"]); name == tag {
				return "", errTelegramScope
			}
		}
		options := option.PokrovTelegramWSOutboundOptions{DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: bindInterface}}, VPNOutbound: vpnTag,
			Datacenters: datacenters, ServiceID: serviceID, IssuedAt: verified.issuedAt, ExpiresAt: verified.expiresAt}
		options.NativePreparationID, err = telegramws.RegisterPreparation(options, fallback)
		if err != nil {
			return "", errTelegramScope
		}
		encoded, _ := json.Marshal(options)
		var row map[string]json.RawMessage
		_ = json.Unmarshal(encoded, &row)
		row["type"], _ = json.Marshal(telegramws.Type)
		row["tag"], _ = json.Marshal(tag)
		outbounds = append(outbounds, row)
		var exactIPs []string
		for _, dc := range datacenters {
			for _, address := range dc.Addresses {
				if usedAddresses[address] {
					return "", errTelegramScope
				}
				usedAddresses[address] = true
				exactIPs = append(exactIPs, address+"/32")
				if strings.Contains(address, ":") {
					exactIPs[len(exactIPs)-1] = address + "/128"
				}
			}
		}
		sort.Strings(exactIPs)
		encoded, _ = json.Marshal(map[string]any{"action": "route", "network": "tcp", "port": 443, "ip_cidr": exactIPs, "outbound": tag})
		var rule map[string]json.RawMessage
		_ = json.Unmarshal(encoded, &rule)
		telegramRules = append(telegramRules, rule)
		prepared.Services = append(prepared.Services, telegramPreparedService{serviceID, tag})
		prepared.IssuedAt, prepared.ExpiresAt = verified.issuedAt, verified.expiresAt
	}
	config["outbounds"], _ = json.Marshal(outbounds)
	// Preserve the existing protected/manual/application prefix. The first
	// catalog window is the current curated-service layer; exact TG rules
	// precede it and its same-service DPI projection, but never user choices.
	insertAt := 0
	for i, rule := range rules {
		if rule["pokrov_catalog_window"] != nil {
			insertAt = i
			break
		}
	}
	combined := append(append(append([]map[string]json.RawMessage(nil), rules[:insertAt]...), telegramRules...), rules[insertAt:]...)
	route["rules"], _ = json.Marshal(combined)
	config["route"], _ = json.Marshal(route)
	prepared.Profile, _ = json.Marshal(config)
	encoded, err := json.Marshal(prepared)
	return string(encoded), err
}

func telegramHasServiceVPNRule(rules []map[string]json.RawMessage, verified *verifiedCatalogService, serviceID, vpnTag string) bool {
	domains, valid := localDpiCatalogArray(verified.service["domains"], 0, 256)
	if !valid {
		return false
	}
	for _, rule := range rules {
		var window map[string]json.RawMessage
		if json.Unmarshal(rule["pokrov_catalog_window"], &window) != nil {
			continue
		}
		id, _ := localDpiCatalogString(window["service_id"])
		issued, _ := localDpiCatalogString(window["issued_at"])
		expires, _ := localDpiCatalogString(window["expires_at"])
		tag, _ := localDpiCatalogString(rule["outbound"])
		action, _ := localDpiCatalogString(rule["action"])
		if id != serviceID || issued != verified.issuedAt || expires != verified.expiresAt || tag != vpnTag || action != "route" || window["lease_id"] != nil || window["lease_group"] != nil ||
			rule["domain_regex"] != nil || rule["domain_keyword"] != nil || rule["ip_cidr"] != nil || rule["ip_is_private"] != nil || rule["rule_set"] != nil {
			continue
		}
		for _, raw := range domains {
			domain, valid := smartAccessControlObject(raw, "name", "match", "role", "shared", "source_ids")
			name, _ := localDpiCatalogString(domain["name"])
			match, _ := localDpiCatalogString(domain["match"])
			if !valid || !localDpiCatalogHost(name) || string(domain["shared"]) != "false" {
				continue
			}
			key, other := "domain", "domain_suffix"
			if match == "suffix" {
				key, other = other, key
			} else if match != "exact" {
				continue
			}
			var names []string
			if rule[other] == nil && json.Unmarshal(rule[key], &names) == nil && len(names) == 1 && names[0] == name {
				return true
			}
		}
	}
	return false
}

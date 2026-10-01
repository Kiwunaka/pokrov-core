//go:build pokrov_client

package include

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestClientRegistryExcludesUnusedProtocolsAndServers(t *testing.T) {
	outbounds := OutboundRegistry()
	for _, protocol := range []string{"psiphon", "tor", "mieru", "dnstt", "ssh"} {
		if _, exists := outbounds.CreateOptions(protocol); exists {
			t.Errorf("client registered unused outbound %q", protocol)
		}
	}
	inbounds := InboundRegistry()
	for _, protocol := range []string{"direct", "shadowsocks", "vmess", "trojan", "naive", "shadowtls", "vless", "anytls", "mieru", "ssh", "hysteria", "hysteria2", "tuic"} {
		if _, exists := inbounds.CreateOptions(protocol); exists {
			t.Errorf("client registered server inbound %q", protocol)
		}
	}
	for _, protocol := range []string{"tun", "socks", "http", "mixed"} {
		if _, exists := inbounds.CreateOptions(protocol); !exists {
			t.Errorf("client lost local inbound %q", protocol)
		}
	}
	for _, protocol := range []string{"direct", "vless", "selector", "pokrov-telegram-ws", "pokrov-local-dpi"} {
		if _, exists := outbounds.CreateOptions(protocol); !exists {
			t.Errorf("client lost outbound %q", protocol)
		}
	}
	var inventory struct {
		Schema   int      `json:"schema"`
		Features []string `json:"features"`
	}
	if err := json.Unmarshal([]byte(TransportCapabilities()), &inventory); err != nil ||
		inventory.Schema != 1 || !slices.Contains(inventory.Features, "pokrov_telegram_ws_v1") {
		t.Fatal("registered Telegram WSS support missing from transport inventory")
	}
}

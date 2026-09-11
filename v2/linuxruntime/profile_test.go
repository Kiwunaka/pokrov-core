package linuxruntime

import (
	"encoding/json"
	"strings"
	"testing"
)

const syntheticProfile = `{"dns":{"servers":[{"type":"https","tag":"remote","server":"1.1.1.1"}]},"inbounds":[{"type":"tun","tag":"tun-in","mtu":1400,"address":["172.19.0.1/28"],"auto_route":true}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[],"final":"direct"}}`

func TestPrepareOwnsNetworkingAndKeepsDNS(t *testing.T) {
	data, plan, err := Prepare([]byte(syntheticProfile))
	if err != nil {
		t.Fatal(err)
	}
	if plan.TunnelInterface != "pokrov0" || plan.RoutingMark != 0x504b || len(plan.DNSServers) != 1 || plan.DNSServers[0] != "172.19.0.2" {
		t.Fatal("unexpected network plan")
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	tun := result["inbounds"].([]any)[0].(map[string]any)
	if tun["interface_name"] != plan.TunnelInterface || tun["auto_redirect"] != false || tun["auto_route"] != false || tun["strict_route"] != true {
		t.Fatal("profile controls TUN ownership")
	}
	if !strings.Contains(string(data), `"type":"https"`) || result["log"].(map[string]any)["disabled"] != true {
		t.Fatal("DNS transport or log policy changed")
	}
}

func TestPrepareRejectsPrivilegedProfileSurfaces(t *testing.T) {
	for name, replacement := range map[string]string{
		"file TLS key":         `{"type":"trojan","tls":{"client_key_path":"/root/private"}}`,
		"namespace":            `{"type":"direct","netns":"owned-by-someone-else"}`,
		"external process":     `{"type":"tor"}`,
		"foreign routing mark": `{"type":"direct","routing_mark":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(syntheticProfile, `{"type":"direct","tag":"direct"}`, replacement, 1)
			if _, _, err := Prepare([]byte(input)); err != ErrProfile {
				t.Fatal("privileged surface accepted")
			}
		})
	}
	for _, input := range []string{
		strings.Replace(syntheticProfile, `"mtu":1400`, `"mtu":1400,"interface_name":"eth0"`, 1),
		strings.Replace(syntheticProfile, `"rules":[]`, `"rules":[],"rule_set":[{"type":"local","path":"/etc/private"}]`, 1),
		strings.Replace(syntheticProfile, `"dns":`, `"experimental":{"clash_api":{"external_controller":"0.0.0.0:80"}},"dns":`, 1),
	} {
		if _, _, err := Prepare([]byte(input)); err != ErrProfile {
			t.Fatal("privileged profile accepted")
		}
	}
}

func TestPrepareAllowsWebSocketTransportPath(t *testing.T) {
	input := strings.Replace(syntheticProfile, `{"type":"direct","tag":"direct"}`, `{"type":"vless","tag":"proxy","transport":{"type":"ws","path":"/tunnel"}}`, 1)
	if _, _, err := Prepare([]byte(input)); err != nil {
		t.Fatal(err)
	}
}

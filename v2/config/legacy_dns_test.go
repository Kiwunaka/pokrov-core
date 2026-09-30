package config

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

const legacyDNSProfile = `{
	"dns":{"servers":[{"tag":"bootstrap","address":"local"},
	 {"tag":"tunnel","address":"8.8.8.8","detour":"countries"}],"final":"tunnel",
	 "rules":[{"domain_suffix":["example.invalid"],"server":"tunnel"}],"strategy":"prefer_ipv4"},
	"outbounds":[{"type":"selector","tag":"countries","outbounds":["reserved"],"default":"reserved"},
	 {"type":"vless","tag":"reserved","server":"192.0.2.1","server_port":443,
	 "uuid":"00000000-0000-4000-8000-000000000001","flow":"xtls-rprx-vision",
	 "tls":{"enabled":true,"server_name":"example.invalid","utls":{"enabled":true,"fingerprint":"chrome"},
	 "reality":{"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"01"}}},
	 {"type":"direct","tag":"direct"},{"type":"dns","tag":"dns-out"}],
	"route":{"final":"countries","default_domain_resolver":{"server":"bootstrap","strategy":"prefer_ipv4"},
	 "rules":[{"protocol":"dns","outbound":"dns-out"},{"domain_suffix":["direct.invalid"],"outbound":"direct"}]},
	"_meta":{"title":"synthetic managed profile"}}
`

func TestNormalizeLegacyDNSPreservesManagedProfile(t *testing.T) {
	input := []byte(legacyDNSProfile)
	before := append([]byte(nil), input...)
	normalized, err := NormalizeLegacyDNS(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, before) {
		t.Fatal("normalization modified the caller's profile")
	}
	var original, result map[string]any
	_ = json.Unmarshal(input, &original)
	_ = json.Unmarshal(normalized, &result)
	if result["_meta"] != nil {
		t.Fatal("Portal metadata reached runtime options")
	}
	original["outbounds"] = original["outbounds"].([]any)[:3]
	rule := original["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	delete(rule, "outbound")
	rule["action"] = "hijack-dns"
	for _, field := range []string{"outbounds", "route"} {
		if !reflect.DeepEqual(original[field], result[field]) {
			t.Fatalf("normalization rewrote %s", field)
		}
	}
	oldDNS := original["dns"].(map[string]any)
	newDNS := result["dns"].(map[string]any)
	for _, field := range []string{"rules", "final", "strategy"} {
		if !reflect.DeepEqual(oldDNS[field], newDNS[field]) {
			t.Fatalf("normalization rewrote DNS %s", field)
		}
	}
	ctx := libbox.BaseContext(nil)
	for _, read := range []func() (*option.Options, error){
		func() (*option.Options, error) { return ReadSingOptions(ctx, &ReadOptions{Content: legacyDNSProfile}) },
		func() (*option.Options, error) {
			return ParseConfig(ctx, &ReadOptions{Content: legacyDNSProfile}, false, DefaultPokrovOptions(), true)
		},
	} {
		options, err := read()
		if err != nil {
			t.Fatal(err)
		}
		if options.DNS == nil || options.Route == nil || options.DNS.Final != "tunnel" || options.Route.Final != "countries" {
			t.Fatal("raw/full-config read discarded managed DNS or route")
		}
		if options.DNS.Servers[0].Type != C.DNSTypeLocal || options.DNS.Servers[1].Type != C.DNSTypeUDP {
			t.Fatal("legacy transports were not typed")
		}
		remote := options.DNS.Servers[1].Options.(*option.RemoteDNSServerOptions)
		if remote.Server != "8.8.8.8" || remote.Detour != "countries" || remote.DomainResolver != nil || remote.ConnectTimeout != 0 {
			t.Fatal("UDP migration changed legacy dial options")
		}
	}
	typed, err := NormalizeLegacyDNS(normalized)
	if err != nil || !bytes.Equal(typed, normalized) {
		t.Fatal("typed input did not remain byte-for-byte unchanged")
	}
}

func TestNormalizeLegacyDNSPreservesHTTPSAndQueryOptions(t *testing.T) {
	input := `{"dns":{"servers":[{"tag":"bootstrap","address":"local"},
	 {"tag":"secure","address":"https://resolver.invalid:8443/custom-dns","address_resolver":"bootstrap",
	 "address_strategy":"prefer_ipv6","address_fallback_delay":"250ms"}],
	 "final":"secure","strategy":"ipv4_only","client_subnet":"192.0.2.0/24",
	 "rules":[{"domain_suffix":["example.invalid"],"server":"secure","strategy":"ipv4_only","client_subnet":"192.0.2.0/24"},
	 {"domain":["override.invalid"],"server":"secure","strategy":"prefer_ipv4"}]},
	 "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`
	options, err := ReadSingOptions(libbox.BaseContext(nil), &ReadOptions{Content: input})
	if err != nil {
		t.Fatal(err)
	}
	remote := options.DNS.Servers[1].Options.(*option.RemoteHTTPSDNSServerOptions)
	if remote.Server != "resolver.invalid" || remote.ServerPort != 8443 || remote.Path != "/custom-dns" || remote.Detour != "" ||
		remote.TLS == nil || !remote.TLS.Enabled || remote.DomainResolver.Server != "bootstrap" ||
		remote.DomainResolver.Strategy != option.DomainStrategy(C.DomainStrategyPreferIPv6) || remote.FallbackDelay == 0 {
		t.Fatal("HTTPS migration changed resolver, detour, path, port or TLS")
	}
	if options.DNS.Strategy != option.DomainStrategy(C.DomainStrategyIPv4Only) || options.DNS.ClientSubnet == nil ||
		options.DNS.Rules[0].DefaultOptions.RouteOptions.Strategy != option.DomainStrategy(C.DomainStrategyIPv4Only) ||
		options.DNS.Rules[0].DefaultOptions.RouteOptions.ClientSubnet == nil ||
		options.DNS.Rules[1].DefaultOptions.RouteOptions.Strategy != option.DomainStrategy(C.DomainStrategyPreferIPv4) {
		t.Fatal("global query options or explicit rule override were lost")
	}
}

func TestNormalizeLegacyDNSDirectStartsWithoutDial(t *testing.T) {
	const profile = `{"log":{"disabled":true},"dns":{"servers":[
	 {"tag":"explicit","address":"192.0.2.53","detour":"0"},
	 {"tag":"default","address":"192.0.2.53"},
	 {"tag":"configured","address":"192.0.2.53","detour":"configured-direct"}],"final":"explicit"},
	 "outbounds":[{"type":"direct"},{"type":"direct","tag":"configured-direct","connect_timeout":"5s"}],
	 "route":{"default_interface":"synthetic-uplink"}}`
	ctx := libbox.BaseContext(nil)
	options, err := ReadSingOptions(ctx, &ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range options.DNS.Servers[:2] {
		if server.Options.(*option.RemoteDNSServerOptions).Detour != "" {
			t.Fatal("legacy plain direct must use the typed DNS direct dialer")
		}
	}
	if options.DNS.Servers[2].Options.(*option.RemoteDNSServerOptions).Detour != "configured-direct" ||
		time.Duration(options.Outbounds[1].Options.(*option.DirectOutboundOptions).ConnectTimeout) != 5*time.Second ||
		options.Route.DefaultInterface != "synthetic-uplink" {
		t.Fatal("configured direct or default interface changed")
	}
	instance, err := box.New(box.Options{Context: ctx, Options: *options})
	if err != nil {
		t.Fatal("synthetic DNS instance creation failed")
	}
	defer instance.Close()
	// Starting DNS initializes the detours; this test never queries or dials.
	if err := instance.Start(); err != nil {
		t.Fatal("migrated direct DNS instance failed to start")
	}
}

func TestNormalizeLegacyDNSRejectsUnsupportedOrMalformedServers(t *testing.T) {
	for _, server := range []string{
		`{"address":""}`, `{"address":"rcode://refused"}`, `{"address":"fakeip"}`,
		`{"address":"8.8.8.8","unexpected":true}`, `{"address":"https://resolver.invalid:70000/dns-query"}`,
		`{"address":"https://user:private@resolver.invalid/dns-query"}`, `{"type":"udp","address":"8.8.8.8"}`,
		`{"address":"8.8.8.8","strategy":"ipv4_only"}`, `{"address":"8.8.8.8","client_subnet":"192.0.2.0/24"}`,
	} {
		_, err := ReadSingOptions(libbox.BaseContext(nil), &ReadOptions{Content: `{"dns":{"servers":[` + server + `]}}`})
		if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid DNS input was accepted or leaked into error")
		}
	}
	if _, err := NormalizeLegacyDNS([]byte(`{"dns":{"servers":[{"address":"local"}]}} {}`)); err == nil {
		t.Fatal("normalization discarded trailing invalid JSON")
	}
}

func TestNormalizeLegacyDNSOutboundRejectsDanglingReferences(t *testing.T) {
	for _, profile := range []string{
		`{"outbounds":[{"type":"dns","tag":"dns-out"}],"route":{"final":"dns-out"}}`,
		`{"outbounds":[{"type":"dns","tag":"dns-out"},{"type":"direct","tag":"direct"}]}`,
		`{"outbounds":[{"type":"direct","tag":"direct","detour":"dns-out"},{"type":"dns","tag":"dns-out"}]}`,
		`{"outbounds":[{"type":"selector","tag":"countries","outbounds":["dns-out"]},{"type":"dns","tag":"dns-out"}]}`,
		`{"outbounds":[{"type":"direct","tag":"direct"},{"type":"dns","tag":"dns-out"}],"unknown_extension":true}`,
		`{"outbounds":[{"type":"dns","unexpected":true}]}`,
		`{"outbounds":[{"type":"dns","tag":123}]}`,
		`{"outbounds":[{"type":"dns","tag":"dns-out"}],"route":{"rules":[{"outbound":"dns-out","action":123}]}}`,
	} {
		if _, err := ReadSingOptions(libbox.BaseContext(nil), &ReadOptions{Content: profile}); err == nil {
			t.Fatal("unsupported DNS reference or unknown runtime field was accepted")
		}
	}
}

func TestParseConfigClassifiesNativeXrayAndSingleSingboxOutbound(t *testing.T) {
	const native = `{"outbounds":[
	 {"protocol":"vless","tag":"one","settings":{"vnext":[{"address":"192.0.2.1","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]}]}},
	 {"protocol":"vless","tag":"two"},{"protocol":"vless","tag":"three"},{"protocol":"vless","tag":"four"}],
	 "routing":{"balancers":[{"tag":"countries","selector":["one","two","three","four"]}]}}`
	ctx := libbox.BaseContext(nil)
	_, err := ParseConfig(ctx, &ReadOptions{Content: native}, false, nil, false)
	if err == nil || !strings.HasPrefix(err.Error(), "native Xray JSON is unsupported") || strings.Contains(err.Error(), "192.0.2.1") {
		t.Fatal("native Xray input was misclassified or exposed in the error")
	}
	options, err := ParseConfig(ctx, &ReadOptions{Content: `{"type":"direct","tag":"one"}`}, false, nil, false)
	if err != nil || len(options.Outbounds) != 1 || options.Outbounds[0].Type != C.TypeDirect {
		t.Fatal("single sing-box outbound was not wrapped correctly")
	}
}

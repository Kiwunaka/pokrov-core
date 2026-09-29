package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
)

func TestMixedInboundIsExplicitAndAuthenticated(t *testing.T) {
	host := DefaultPokrovOptions()
	options := &option.Options{}
	setInbound(options, host)
	for _, inbound := range options.Inbounds {
		if inbound.Type == C.TypeMixed {
			t.Fatal("default config exposes a local proxy")
		}
	}
	host.MixedPort = 12334
	options.Inbounds = nil
	setInbound(options, host)
	if err := ValidateProxyInbounds(options); err == nil {
		t.Fatal("explicit proxy port without credentials accepted")
	}
	host.MixedUsers = []auth.User{{Username: "test", Password: "test-password"}}
	options.Inbounds = nil
	setInbound(options, host)
	if err := ValidateProxyInbounds(options); err != nil {
		t.Fatal(err)
	}
	for _, inbound := range options.Inbounds {
		if inbound.Type == C.TypeMixed {
			settings := inbound.Options.(*option.HTTPMixedInboundOptions)
			if settings.Users[0] != host.MixedUsers[0] {
				t.Fatal("proxy credentials were not preserved")
			}
		}
	}
}

func TestTypedProxyInboundRequiresPassword(t *testing.T) {
	users := []auth.User{{Username: "test", Password: "test-password"}}
	options := &option.Options{Inbounds: []option.Inbound{
		{Type: C.TypeSOCKS, Options: option.SocksInboundOptions{Users: users}},
		{Type: C.TypeHTTP, Options: option.HTTPMixedInboundOptions{Users: users}},
		{Type: C.TypeMixed, Options: &option.HTTPMixedInboundOptions{Users: users}},
	}}
	if err := ValidateProxyInbounds(options); err != nil {
		t.Fatal(err)
	}
	users[0].Password = ""
	if err := ValidateProxyInbounds(options); err == nil {
		t.Fatal("empty proxy password accepted")
	}
}

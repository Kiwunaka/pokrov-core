package mobile

import (
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestNormalizeRuntimeConfigForCommandServer(t *testing.T) {
	const saved = `{"dns":{"servers":[{"tag":"local","address":"local"}]},"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`
	if err := libbox.CheckConfig(saved); err == nil {
		t.Fatal("strict CommandServer parser accepted legacy DNS")
	}
	runtimeCopy, err := NormalizeRuntimeConfig(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := libbox.CheckConfig(runtimeCopy); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeRuntimeConfigRequiresProxyAuthentication(t *testing.T) {
	const anonymous = `{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":1080}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	if err := libbox.CheckConfig(anonymous); err != nil {
		t.Fatalf("fixture must be valid for the upstream CommandServer: %v", err)
	}
	if runtimeCopy, err := NormalizeRuntimeConfig(anonymous); err == nil || runtimeCopy != "" {
		t.Fatal("mobile preparation admitted an unauthenticated proxy inbound")
	}

	const authenticated = `{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":1080,"users":[{"username":"test-user","password":"test-password"}]}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	runtimeCopy, err := NormalizeRuntimeConfig(authenticated)
	if err != nil {
		t.Fatal(err)
	}
	if err := libbox.CheckConfig(runtimeCopy); err != nil {
		t.Fatal(err)
	}
}

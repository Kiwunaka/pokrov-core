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

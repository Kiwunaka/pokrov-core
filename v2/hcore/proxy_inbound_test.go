package hcore

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Kiwunaka/POKROV-core/v2/config"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestNewServiceRejectsUnauthenticatedProxy(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	for _, test := range []struct{ protocol, address string }{
		{"socks", "127.0.0.1"},
		{"http", "0.0.0.0"},
		{"mixed", "::1"},
	} {
		t.Run(test.protocol, func(t *testing.T) {
			input := fmt.Sprintf(`{"inbounds":[{"type":%q,"listen":%q,"listen_port":12334}],"outbounds":[{"type":"direct"}]}`, test.protocol, test.address)
			options, err := config.ReadSingOptions(ctx, &config.ReadOptions{Content: input})
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewService(ctx, *options)
			if service != nil || err == nil || !strings.Contains(err.Error(), "requires username and password") {
				t.Fatal("Core did not reject the unauthenticated proxy before startup")
			}
		})
	}
}

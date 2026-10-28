package libbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/protocol/pokrov/slipstream"
	"github.com/sagernet/sing/service"
)

func TestSlipstreamPathIsCapturedFromTrustedHostSetup(t *testing.T) {
	previous := slipstreamClientPath()
	t.Cleanup(func() { SetSlipstreamClientPath(previous) })
	if err := SetSlipstreamClientPath("slipstream-client"); err == nil {
		t.Fatal("host setup accepted a relative executable path")
	}
	client := filepath.Join(t.TempDir(), "slipstream-client")
	if err := os.WriteFile(client, []byte("test host artifact"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SetSlipstreamClientPath(client); err != nil {
		t.Fatal(err)
	}
	captured := FromContext(context.Background(), nil)
	if err := SetSlipstreamClientPath(""); err != nil {
		t.Fatal(err)
	}
	if string(service.FromContext[slipstream.ExecutablePath](captured)) != client ||
		service.FromContext[slipstream.ExecutablePath](FromContext(context.Background(), nil)) != "" {
		t.Fatal("host path replacement changed an existing runtime context")
	}
}

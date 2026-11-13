package psiphon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service/filemanager"
)

func TestNetworkChangeBeforeControllerStartAndClose(t *testing.T) {
	root := t.TempDir()
	ctx := filemanager.WithDefault(context.Background(), root, root, os.Getuid(), os.Getgid())
	config, err := buildConfig(ctx, option.PsiphonOutboundOptions{DataDirectory: "psiphon"}, defaultEstablishTunnelTimeout, "reserve")
	if err != nil {
		t.Fatal(err)
	}
	if config.DataRootDirectory != filepath.Join(root, "psiphon", instanceDirectory("reserve")) {
		t.Fatal("relative data directory escaped the runtime directory")
	}
	logger := log.NewNOPFactory().Logger()
	controller, err := NewPsiphon(ctx, logger, config, "reserve")
	if err != nil {
		t.Fatal(err)
	}
	outbound := &Outbound{psiphon: controller, logger: logger}
	// Android reports network changes while a cold Psiphon controller is still
	// being created. The callback must not dereference a missing controller.
	outbound.InterfaceUpdated(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = controller.Dial(ctx, "example.test:443", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("pending dial did not honor cancellation")
	}
	if err = outbound.Close(); err != nil {
		t.Fatal(err)
	}
	if err = controller.Start(); !errors.Is(err, context.Canceled) {
		t.Fatal("closed controller restarted")
	}
}

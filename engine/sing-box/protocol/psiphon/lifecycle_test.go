package psiphon

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestNetworkChangeBeforeControllerStartAndClose(t *testing.T) {
	config, err := buildConfig(option.PsiphonOutboundOptions{DataDirectory: t.TempDir()}, defaultEstablishTunnelTimeout, "reserve")
	if err != nil {
		t.Fatal(err)
	}
	logger := log.NewNOPFactory().Logger()
	controller, err := NewPsiphon(context.Background(), logger, config, "reserve")
	if err != nil {
		t.Fatal(err)
	}
	outbound := &Outbound{psiphon: controller, logger: logger}
	// Android reports network changes while a cold Psiphon controller is still
	// being created. The callback must not dereference a missing controller.
	outbound.InterfaceUpdated(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
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

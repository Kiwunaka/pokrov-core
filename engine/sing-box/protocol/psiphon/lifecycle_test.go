package psiphon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

type protectedNetwork struct {
	adapter.NetworkManager
	protected bool
}

func (*protectedNetwork) InterfaceFinder() control.InterfaceFinder { return nil }
func (*protectedNetwork) AutoDetectInterface() bool                { return false }
func (*protectedNetwork) DefaultOptions() adapter.NetworkOptions   { return adapter.NetworkOptions{} }
func (*protectedNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }
func (n *protectedNetwork) ProtectFunc() control.Func {
	return func(string, string, syscall.RawConn) error { n.protected = true; return nil }
}

type bootstrapTransports struct{ adapter.DNSTransportManager }

func (bootstrapTransports) Transports() []adapter.DNSTransport { return nil }
func (bootstrapTransports) Default() adapter.DNSTransport      { return nil }

func TestProviderSocketIsProtectedWithoutInterfaceAutoDetection(t *testing.T) {
	network := &protectedNetwork{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), network)
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, bootstrapTransports{})
	out, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "psiphon", option.PsiphonOutboundOptions{DataDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	provider := out.(*Outbound)
	defer provider.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := provider.dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !network.protected {
		t.Fatal("provider socket bypassed platform protection")
	}
}

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
	if !config.DisableTactics || len(config.LimitTunnelProtocols) != 1 || config.LimitTunnelProtocols[0] != "FRONTED-MEEK-OSSH" {
		t.Fatal("cached tactics can replace the HTTPS carrier")
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

package awg

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/sagernet/sing/common/metadata"
)

type networkTun struct {
	tun.Device
	conn        *netstack.Net
	startReady  chan struct{}
	startOnce   sync.Once
	readStarted bool
}

func newNetworkTun(address []netip.Prefix, mtu uint32) (tunAdapter, error) {
	var localAddresses []netip.Addr
	for _, prefix := range address {
		localAddresses = append(localAddresses, prefix.Addr())
	}

	tun, conn, err := netstack.CreateNetTUN(localAddresses, []netip.Addr{}, int(mtu))
	if err != nil {
		return nil, err
	}

	return &networkTun{
		Device:     tun,
		conn:       conn,
		startReady: make(chan struct{}),
	}, nil
}

func (t *networkTun) Start() error {
	t.startOnce.Do(func() { close(t.startReady) })
	return nil
}

func (t *networkTun) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	if !t.readStarted {
		t.readStarted = true
		<-t.startReady
		// The pinned engine snapshots S4 before Read, even before IpcSet.
		// Return no packet once so its sole TUN reader reloads configured S4.
		return 0, nil
	}
	return t.Device.Read(packets, sizes, offset)
}

func (t *networkTun) Close() error {
	err := t.Device.Close()
	t.startOnce.Do(func() { close(t.startReady) })
	return err
}

func (t *networkTun) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	return t.conn.DialContext(ctx, network, destination.String())
}

func (t *networkTun) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	return t.conn.DialUDPAddrPort(netip.AddrPort{}, destination.AddrPort())
}

package awg

import (
	"context"
	"net"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/exceptions"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

type DeviceOpts struct {
	UseIntegratedTun bool
	Address          []netip.Prefix
	AllowedIps       []netip.Prefix
	ExcludedIps      []netip.Prefix
	MTU              uint32
}

type Device struct {
	awgDevice *device.Device
	tun       tunAdapter
	bind      conn.Bind
	logger    *device.Logger
	ipcConfig string
}

func NewDevice(ctx context.Context, logger logger.ContextLogger, dial network.Dialer, ipcConfig string, opts DeviceOpts) (*Device, error) {
	var (
		tun tunAdapter
		err error
	)

	if opts.UseIntegratedTun {
		tun, err = newSystemTun(ctx, opts.Address, opts.AllowedIps, opts.ExcludedIps, opts.MTU, logger)
		if err != nil {
			return nil, exceptions.Cause(err, "create tunnel")
		}
	} else {
		tun, err = newNetworkTun(opts.Address, opts.MTU)
		if err != nil {
			return nil, err
		}
	}

	return &Device{
		tun:       tun,
		bind:      newBind(ctx, dial),
		logger:    newSafeDeviceLogger(logger),
		ipcConfig: ipcConfig,
	}, nil
}

func (d *Device) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	d.awgDevice = device.NewDevice(d.tun, d.bind, d.logger)
	if err := d.awgDevice.IpcSet(d.ipcConfig); err != nil {
		d.awgDevice.Close()
		d.awgDevice = nil
		return E.Cause(err, "set ipc config")
	}

	if err := d.tun.Start(); err != nil {
		d.awgDevice.Close()
		d.awgDevice = nil
		return E.Cause(err, "tun start")
	}

	if err := d.awgDevice.Up(); err != nil {
		d.awgDevice.Close()
		d.awgDevice = nil
		return err
	}
	return nil
}

func (d *Device) Close() error {
	if d.awgDevice == nil {
		return nil
	}
	d.awgDevice.Close()
	d.awgDevice = nil
	return nil
}

func (d *Device) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	return d.tun.DialContext(ctx, network, destination)
}

func (d *Device) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	return d.tun.ListenPacket(ctx, destination)
}

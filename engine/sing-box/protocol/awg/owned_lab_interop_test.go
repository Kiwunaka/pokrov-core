package awg

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	awgtransport "github.com/sagernet/sing-box/transport/awg"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestOwnedAWGLabAuthenticatedEgress is an operator-only interop gate. Real
// endpoint material enters through the process environment and is never
// retained in source, fixtures, logs, or test failures.
func TestOwnedAWGLabAuthenticatedEgress(t *testing.T) {
	encoded := os.Getenv("POKROV_OWNED_AWG_ENDPOINT_B64")
	if encoded == "" {
		t.Skip("owned AWG endpoint is not available")
	}
	t.Cleanup(func() { _ = os.Unsetenv("POKROV_OWNED_AWG_ENDPOINT_B64") })

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal("owned AWG endpoint encoding is invalid")
	}
	t.Cleanup(func() {
		for index := range raw {
			raw[index] = 0
		}
	})

	var endpointOptions option.AwgEndpointOptions
	if err := json.Unmarshal(raw, &endpointOptions); err != nil {
		t.Fatal("owned AWG endpoint JSON is invalid")
	}
	if err := validateEndpointOptions(endpointOptions); err != nil {
		t.Fatal("owned AWG endpoint violates the pinned contract")
	}
	ipc, err := genIpcConfig(endpointOptions)
	if err != nil {
		t.Fatal("owned AWG endpoint IPC generation failed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	defaultDialer, err := dialer.NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		t.Fatal("owned AWG default dialer creation failed")
	}
	observedDialer := &ownedLabObservedDialer{Dialer: defaultDialer}
	device, err := awgtransport.NewDevice(
		ctx,
		log.NewNOPFactory().Logger(),
		observedDialer,
		ipc,
		awgtransport.DeviceOpts{
			UseIntegratedTun: false,
			Address:          endpointOptions.Address,
			AllowedIps:       endpointOptions.Peers[0].AllowedIPs,
			MTU:              endpointOptions.MTU,
		},
	)
	if err != nil {
		t.Fatal("owned AWG device creation failed")
	}
	defer device.Close()
	if err := device.Start(adapter.StartStateStart); err != nil {
		t.Fatal("owned AWG device start failed")
	}

	destination, err := resolveOwnedProbeIPv4(ctx)
	if err != nil {
		t.Fatal("owned egress probe resolution failed")
	}
	connection, err := device.DialContext(
		ctx,
		N.NetworkTCP,
		M.Socksaddr{Addr: destination, Port: 443},
	)
	if err != nil {
		if observedDialer.writeCount.Load() == 0 {
			t.Fatal("owned AWG TCP egress failed before an outer packet was emitted")
		}
		if observedDialer.writeErrorCount.Load() > 0 {
			t.Fatal("owned AWG TCP egress failed after an outer packet write error")
		}
		if observedDialer.readCount.Load() == 0 {
			t.Fatal("owned AWG TCP egress failed because no outer response was received")
		}
		t.Fatal("owned AWG TCP egress failed after outer responses were received")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))

	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "api.pokrov.space",
	})
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		t.Fatal("owned AWG TLS egress failed")
	}
	defer tlsConnection.Close()
	if _, err := tlsConnection.Write([]byte(
		"GET /api/public/authenticated-egress-probe HTTP/1.1\r\n" +
			"Host: api.pokrov.space\r\n" +
			"Connection: close\r\n\r\n",
	)); err != nil {
		t.Fatal("owned AWG HTTP request failed")
	}
	response, err := http.ReadResponse(
		bufio.NewReader(tlsConnection),
		&http.Request{Method: http.MethodGet},
	)
	if err != nil {
		t.Fatal("owned AWG HTTP response failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent ||
		response.Header.Get("X-Pokrov-Egress-Probe") != "pokrov-authenticated-egress-v1" {
		t.Fatal("owned AWG authenticated egress marker mismatch")
	}
}

type ownedLabObservedDialer struct {
	N.Dialer
	writeCount      atomic.Int64
	writeErrorCount atomic.Int64
	readCount       atomic.Int64
}

func (d *ownedLabObservedDialer) ListenPacket(
	ctx context.Context,
	destination M.Socksaddr,
) (net.PacketConn, error) {
	packetConnection, err := d.Dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return &ownedLabObservedPacketConnection{
		PacketConn:      packetConnection,
		writeCount:      &d.writeCount,
		writeErrorCount: &d.writeErrorCount,
		readCount:       &d.readCount,
	}, nil
}

type ownedLabObservedPacketConnection struct {
	net.PacketConn
	writeCount      *atomic.Int64
	writeErrorCount *atomic.Int64
	readCount       *atomic.Int64
}

func (c *ownedLabObservedPacketConnection) ReadFrom(payload []byte) (int, net.Addr, error) {
	read, source, err := c.PacketConn.ReadFrom(payload)
	if read > 0 {
		c.readCount.Add(1)
	}
	return read, source, err
}

func (c *ownedLabObservedPacketConnection) WriteTo(
	payload []byte,
	destination net.Addr,
) (int, error) {
	written, err := c.PacketConn.WriteTo(payload, destination)
	if written > 0 {
		c.writeCount.Add(1)
	}
	if err != nil {
		c.writeErrorCount.Add(1)
	}
	return written, err
}

func resolveOwnedProbeIPv4(ctx context.Context) (netip.Addr, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "api.pokrov.space")
	if err != nil {
		return netip.Addr{}, err
	}
	for _, address := range addresses {
		if address.Is4() {
			return address, nil
		}
	}
	return netip.Addr{}, &net.DNSError{Err: "IPv4 address unavailable", Name: "api.pokrov.space"}
}

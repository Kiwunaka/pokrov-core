package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type bindTestListenResult struct {
	conn net.PacketConn
	err  error
}

type bindTestDialer struct {
	results []bindTestListenResult
	calls   []M.Socksaddr
}

func (d *bindTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unexpected DialContext call")
}

func (d *bindTestDialer) ListenPacket(_ context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.calls = append(d.calls, destination)
	if len(d.results) == 0 {
		return nil, errors.New("unexpected ListenPacket call")
	}
	result := d.results[0]
	d.results = d.results[1:]
	return result.conn, result.err
}

type bindTestPacketConn struct {
	localAddr net.Addr
	mutex     sync.Mutex
	closed    bool
}

func (c *bindTestPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("unexpected ReadFrom call")
}

func (c *bindTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}

func (c *bindTestPacketConn) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.closed = true
	return nil
}

func (c *bindTestPacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *bindTestPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *bindTestPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *bindTestPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *bindTestPacketConn) isClosed() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.closed
}

func TestBindOpenReturnsAllocatedPortAndRequestsItForIPv6(t *testing.T) {
	const allocatedPort = 41234
	dialer := &bindTestDialer{results: []bindTestListenResult{
		{conn: &bindTestPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4zero, Port: allocatedPort}}},
		{conn: &bindTestPacketConn{localAddr: &net.UDPAddr{IP: net.IPv6zero, Port: allocatedPort}}},
	}}
	bind := newBind(context.Background(), dialer).(*bind_adapter)

	receiveFns, actualPort, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer bind.Close()

	if actualPort != allocatedPort {
		t.Fatalf("actual port = %d, want %d", actualPort, allocatedPort)
	}
	if len(receiveFns) != 2 {
		t.Fatalf("receive function count = %d, want 2", len(receiveFns))
	}
	if len(dialer.calls) != 2 {
		t.Fatalf("ListenPacket call count = %d, want 2", len(dialer.calls))
	}
	if dialer.calls[0].Addr != netip.IPv4Unspecified() || dialer.calls[0].Port != 0 {
		t.Fatalf("unexpected IPv4 bind request: %v", dialer.calls[0])
	}
	if dialer.calls[1].Addr != netip.IPv6Unspecified() || dialer.calls[1].Port != allocatedPort {
		t.Fatalf("unexpected IPv6 bind request: %v", dialer.calls[1])
	}
}

func TestBindOpenUsesIPv6PortWhenIPv4IsUnavailable(t *testing.T) {
	const allocatedPort = 42345
	dialer := &bindTestDialer{results: []bindTestListenResult{
		{err: syscall.EAFNOSUPPORT},
		{conn: &bindTestPacketConn{localAddr: &net.UDPAddr{IP: net.IPv6zero, Port: allocatedPort}}},
	}}
	bind := newBind(context.Background(), dialer).(*bind_adapter)

	receiveFns, actualPort, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer bind.Close()

	if actualPort != allocatedPort {
		t.Fatalf("actual port = %d, want %d", actualPort, allocatedPort)
	}
	if len(receiveFns) != 1 {
		t.Fatalf("receive function count = %d, want 1", len(receiveFns))
	}
}

func TestBindOpenClosesIPv4ConnectionWhenIPv6OpenFails(t *testing.T) {
	conn4 := &bindTestPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 43456}}
	dialer := &bindTestDialer{results: []bindTestListenResult{
		{conn: conn4},
		{err: errors.New("ipv6 open failed")},
	}}
	bind := newBind(context.Background(), dialer).(*bind_adapter)

	if _, _, err := bind.Open(0); err == nil {
		t.Fatal("Open succeeded, want IPv6 failure")
	}
	if !conn4.isClosed() {
		t.Fatal("IPv4 connection remained open after IPv6 failure")
	}
	if bind.conn4 != nil || bind.conn6 != nil {
		t.Fatal("failed Open retained packet connections")
	}
}

func TestBindOpenFailsWhenNoAddressFamilyIsAvailable(t *testing.T) {
	dialer := &bindTestDialer{results: []bindTestListenResult{
		{err: syscall.EAFNOSUPPORT},
		{err: syscall.EAFNOSUPPORT},
	}}
	bind := newBind(context.Background(), dialer).(*bind_adapter)

	if _, _, err := bind.Open(0); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("Open error = %v, want EAFNOSUPPORT", err)
	}
}

func TestBindOpenClosesConnectionWithoutAllocatedPort(t *testing.T) {
	conn4 := &bindTestPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4zero}}
	dialer := &bindTestDialer{results: []bindTestListenResult{{conn: conn4}}}
	bind := newBind(context.Background(), dialer).(*bind_adapter)

	if _, _, err := bind.Open(0); err == nil {
		t.Fatal("Open succeeded without an allocated port")
	}
	if !conn4.isClosed() {
		t.Fatal("connection without an allocated port remained open")
	}
}

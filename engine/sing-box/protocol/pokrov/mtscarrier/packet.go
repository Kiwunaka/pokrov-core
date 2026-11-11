package mts

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"
)

// PacketConn maps board broadcasts to KCP datagrams. Each client owns a random ID.
type packetCarrier interface {
	Send([]byte) error
	Receive(func([]byte))
	Stop() error
}

type PacketConn struct {
	carrier  packetCarrier
	server   bool
	id       [16]byte
	incoming chan packet
	done     chan struct{}
	once     sync.Once
}
type packet struct {
	data []byte
	addr packetAddr
}
type packetAddr [16]byte

func (a packetAddr) Network() string { return "mts" }
func (a packetAddr) String() string  { return hex.EncodeToString(a[:]) }
func NewPacketConn(carrier packetCarrier, server bool) (*PacketConn, error) {
	p := &PacketConn{carrier: carrier, server: server, incoming: make(chan packet, 1024), done: make(chan struct{})}
	if !server {
		if _, err := rand.Read(p.id[:]); err != nil {
			return nil, err
		}
	}
	carrier.Receive(func(data []byte) {
		if len(data) < 22 || len(data) > 1221 || string(data[:4]) != "PMT1" {
			return
		}
		direction := byte(1)
		if server {
			direction = 0
		}
		if data[4] != direction {
			return
		}
		var id packetAddr
		copy(id[:], data[5:21])
		if !server && id != packetAddr(p.id) {
			return
		}
		b := append([]byte(nil), data[21:]...)
		select {
		case p.incoming <- packet{b, id}:
		default:
		}
	})
	return p, nil
}
func (p *PacketConn) Peer() net.Addr { return packetAddr(p.id) }
func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case x := <-p.incoming:
		return copy(b, x.data), x.addr, nil
	case <-p.done:
		return 0, nil, net.ErrClosed
	}
}
func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	id, ok := addr.(packetAddr)
	if !ok {
		return 0, errors.New("invalid mts address")
	}
	f := make([]byte, 21+len(b))
	copy(f, "PMT1")
	if p.server {
		f[4] = 1
	}
	copy(f[5:21], id[:])
	copy(f[21:], b)
	if err := p.carrier.Send(f); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (p *PacketConn) Close() error                     { p.once.Do(func() { close(p.done); p.carrier.Stop() }); return nil }
func (p *PacketConn) LocalAddr() net.Addr              { return packetAddr(p.id) }
func (p *PacketConn) SetDeadline(time.Time) error      { return nil }
func (p *PacketConn) SetReadDeadline(time.Time) error  { return nil }
func (p *PacketConn) SetWriteDeadline(time.Time) error { return nil }

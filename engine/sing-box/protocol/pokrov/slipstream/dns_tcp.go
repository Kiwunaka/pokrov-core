package slipstream

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	tcpDNSInitialWorkers  = 8
	tcpDNSMaxWorkers      = 112
	tcpDNSProviderWorkers = 16
)

// Each connection owns one outstanding request. A resolver closing or limiting
// a pipelined connection must not strand the native client's other DNS queries.
type tcpDNSPool struct {
	ctx         context.Context
	cancel      context.CancelFunc
	dialer      N.Dialer
	destination M.Socksaddr
	jobs        chan []byte
	replies     chan []byte
	done        chan struct{}
	inflight    atomic.Int32
	mu          sync.Mutex
	workers     int
	maxWorkers  int
	closed      bool
	connections map[net.Conn]struct{}
	wait        sync.WaitGroup
}

func newTCPDNSPool(ctx context.Context, dialer N.Dialer, destination M.Socksaddr, seed net.Conn) *tcpDNSPool {
	ctx, cancel := context.WithCancel(ctx)
	// ISP resolvers can close the entire pool when too many connections open.
	// The larger budget is verified on the supported public Yandex resolvers.
	maxWorkers := tcpDNSProviderWorkers
	if destination.Port == 53 && (destination.Addr == netip.MustParseAddr("77.88.8.8") || destination.Addr == netip.MustParseAddr("77.88.8.1") || destination.Addr == netip.MustParseAddr("77.88.8.88") || destination.Addr == netip.MustParseAddr("77.88.8.2")) {
		maxWorkers = tcpDNSMaxWorkers
	}
	p := &tcpDNSPool{ctx: ctx, cancel: cancel, dialer: dialer, destination: destination,
		jobs: make(chan []byte, 2*maxWorkers), replies: make(chan []byte, maxWorkers), maxWorkers: maxWorkers,
		done: make(chan struct{}), connections: map[net.Conn]struct{}{seed: {}}}
	p.startWorker(seed)
	for range tcpDNSInitialWorkers - 1 {
		p.startWorker(nil)
	}
	return p
}

// The caller holds mu after construction. Idle workers do not open sockets.
func (p *tcpDNSPool) startWorker(connection net.Conn) {
	p.workers++
	p.wait.Add(1)
	go p.work(connection)
}

func (p *tcpDNSPool) Write(packet []byte) (int, error) {
	var query dns.Msg
	if query.Unpack(packet) != nil || query.Response || len(query.Question) != 1 {
		return 0, errors.New("invalid slipstream DNS request")
	}
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case p.jobs <- append([]byte(nil), packet...):
	default:
		// This bridge carries datagrams; QUIC retries a dropped query.
		// One saturated resolver must not block queries to the other paths.
		return len(packet), nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	if int(p.inflight.Load())+len(p.jobs) > p.workers && p.workers < p.maxWorkers {
		additional := min(p.workers, p.maxWorkers-p.workers)
		for range additional {
			p.startWorker(nil)
		}
	}
	p.mu.Unlock()
	return len(packet), nil
}

func (p *tcpDNSPool) Read(buffer []byte) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case packet := <-p.replies:
		if len(packet) > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		return copy(buffer, packet), nil
	}
}

func (p *tcpDNSPool) Close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.done)
		p.cancel()
		for connection := range p.connections {
			connection.Close()
		}
	}
	p.mu.Unlock()
	p.wait.Wait()
	return nil
}

func (p *tcpDNSPool) release(connection net.Conn) {
	if connection == nil {
		return
	}
	connection.Close()
	p.mu.Lock()
	delete(p.connections, connection)
	p.mu.Unlock()
}

func (p *tcpDNSPool) connect() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(p.ctx, 3*time.Second)
	defer cancel()
	connection, err := p.dialer.DialContext(ctx, N.NetworkTCP, p.destination)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		connection.Close()
		return nil, net.ErrClosed
	}
	p.connections[connection] = struct{}{}
	return connection, nil
}

func (p *tcpDNSPool) work(connection net.Conn) {
	defer p.wait.Done()
	defer func() { p.release(connection) }()
	for {
		var packet []byte
		select {
		case <-p.ctx.Done():
			return
		case packet = <-p.jobs:
		}
		p.inflight.Add(1)
		for attempt := 0; attempt < 2 && p.ctx.Err() == nil; attempt++ {
			var err error
			if connection == nil {
				connection, err = p.connect()
				if err != nil {
					continue
				}
			}
			reply, err := exchangeTCPDNS(connection, packet)
			if err != nil {
				p.release(connection)
				connection = nil
				continue
			}
			select {
			case p.replies <- reply:
			case <-p.ctx.Done():
			}
			break
		}
		p.inflight.Add(-1)
	}
}

func exchangeTCPDNS(connection net.Conn, packet []byte) ([]byte, error) {
	var query dns.Msg
	if err := query.Unpack(packet); err != nil || len(query.Question) != 1 {
		return nil, errors.New("invalid slipstream DNS request")
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	// One request per connection makes random IDs collision-free in flight.
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	originalID := query.Id
	frame := make([]byte, len(packet)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	copy(frame[2:], packet)
	copy(frame[2:4], id[:])
	if err := writeTCPDNSFrame(connection, frame); err != nil {
		return nil, err
	}
	reply, err := readTCPDNSFrame(connection)
	if err != nil {
		return nil, err
	}
	var message dns.Msg
	if message.Unpack(reply) != nil || !message.Response || message.Id != binary.BigEndian.Uint16(id[:]) ||
		len(message.Question) != 1 || message.Question[0].Qtype != query.Question[0].Qtype ||
		message.Question[0].Qclass != query.Question[0].Qclass ||
		!strings.EqualFold(message.Question[0].Name, query.Question[0].Name) {
		return nil, errors.New("slipstream DNS response mismatch")
	}
	binary.BigEndian.PutUint16(reply, originalID)
	return reply, nil
}

// The initial reachability probe runs before workers own the connection.
type framedDNSConn struct{ net.Conn }

func (c framedDNSConn) Read(buffer []byte) (int, error) {
	packet, err := readTCPDNSFrame(c.Conn)
	if err != nil {
		return 0, err
	}
	if len(packet) > len(buffer) {
		return 0, io.ErrShortBuffer
	}
	return copy(buffer, packet), nil
}

func (c framedDNSConn) Write(packet []byte) (int, error) {
	frame := make([]byte, len(packet)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	copy(frame[2:], packet)
	if err := writeTCPDNSFrame(c.Conn, frame); err != nil {
		return 0, err
	}
	return len(packet), nil
}

func writeTCPDNSFrame(connection net.Conn, frame []byte) error {
	for len(frame) > 0 {
		n, err := connection.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func readTCPDNSFrame(connection net.Conn) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(connection, prefix[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length < 12 {
		return nil, io.ErrUnexpectedEOF
	}
	packet := make([]byte, length)
	_, err := io.ReadFull(connection, packet)
	return packet, err
}

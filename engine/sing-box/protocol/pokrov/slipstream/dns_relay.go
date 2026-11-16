package slipstream

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// The native client only sends DNS to loopback. The remote socket belongs to
// Core's protected/bound dialer, including when the client runs as a subprocess.
type dnsRelay struct {
	local    *net.UDPConn
	remotes  []io.ReadWriteCloser
	failed   []atomic.Bool
	left     atomic.Int32
	sequence atomic.Uint64
	auth     localAuth
	peer     netip.AddrPort
	peerLock sync.Mutex
	queries  replayWindow
	once     sync.Once
	wait     sync.WaitGroup
	done     chan struct{}
}

func newDNSRelay(remotes []io.ReadWriteCloser, auth localAuth) (*dnsRelay, error) {
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		for _, remote := range remotes {
			remote.Close()
		}
		return nil, err
	}
	r := &dnsRelay{local: local, remotes: remotes, failed: make([]atomic.Bool, len(remotes)), auth: auth, done: make(chan struct{})}
	r.left.Store(int32(len(remotes)))
	r.wait.Add(1 + len(remotes))
	go r.forwardQueries()
	for index := range remotes {
		go r.forwardReplies(index)
	}
	return r, nil
}

func (r *dnsRelay) setPeer(peer netip.AddrPort) {
	r.peerLock.Lock()
	r.peer = peer
	r.peerLock.Unlock()
}

func (r *dnsRelay) stop() {
	r.once.Do(func() {
		r.local.Close()
		for _, remote := range r.remotes {
			remote.Close()
		}
		close(r.done)
	})
}

func (r *dnsRelay) failPath(index int) {
	if r.failed[index].CompareAndSwap(false, true) {
		r.remotes[index].Close()
		if r.left.Add(-1) == 0 {
			r.stop()
		}
	}
}

func (r *dnsRelay) Close() {
	r.stop()
	r.wait.Wait()
}

func (r *dnsRelay) forwardQueries() {
	defer r.wait.Done()
	defer r.stop()
	packet := make([]byte, 65535)
	for {
		n, peer, err := r.local.ReadFromUDPAddrPort(packet)
		if err != nil {
			return
		}
		payload, sequence, valid := r.auth.openDNS(dnsQuery, packet[:n])
		if !valid || len(payload) < 2 || int(payload[0]) >= len(r.remotes) {
			continue
		}
		r.peerLock.Lock()
		accepted := r.peer == peer && r.queries.accept(sequence)
		r.peerLock.Unlock()
		if accepted {
			index := int(payload[0])
			if !r.failed[index].Load() {
				if _, err = r.remotes[index].Write(payload[1:]); err != nil {
					r.failPath(index)
				}
			}
		}
	}
}

func (r *dnsRelay) forwardReplies(index int) {
	defer r.wait.Done()
	packet := make([]byte, 65507-dnsFrameSize)
	packet[0] = byte(index)
	for {
		n, err := r.remotes[index].Read(packet[1:])
		if err != nil {
			r.failPath(index)
			return
		}
		r.peerLock.Lock()
		peer := r.peer
		r.peerLock.Unlock()
		if peer.IsValid() {
			sequence := r.sequence.Add(1)
			if _, err = r.local.WriteToUDPAddrPort(r.auth.sealDNS(dnsReply, sequence, packet[:n+1]), peer); err != nil {
				r.stop()
				return
			}
		}
	}
}

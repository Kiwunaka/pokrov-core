package slipstream

import (
	"net"
	"net/netip"
	"sync"
)

// The native client only sends DNS to loopback. The remote socket belongs to
// Core's protected/bound dialer, including when the client runs as a subprocess.
type dnsRelay struct {
	local    *net.UDPConn
	remote   net.Conn
	auth     localAuth
	peer     netip.AddrPort
	peerLock sync.Mutex
	queries  replayWindow
	once     sync.Once
	wait     sync.WaitGroup
	done     chan struct{}
}

func newDNSRelay(remote net.Conn, auth localAuth) (*dnsRelay, error) {
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		remote.Close()
		return nil, err
	}
	r := &dnsRelay{local: local, remote: remote, auth: auth, done: make(chan struct{})}
	r.wait.Add(2)
	go r.forwardQueries()
	go r.forwardReplies()
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
		r.remote.Close()
		close(r.done)
	})
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
		if !valid {
			continue
		}
		r.peerLock.Lock()
		accepted := r.peer == peer && r.queries.accept(sequence)
		r.peerLock.Unlock()
		if accepted {
			if _, err = r.remote.Write(payload); err != nil {
				return
			}
		}
	}
}

func (r *dnsRelay) forwardReplies() {
	defer r.wait.Done()
	defer r.stop()
	packet := make([]byte, 65507-dnsFrameSize)
	var sequence uint64
	for {
		n, err := r.remote.Read(packet)
		if err != nil {
			return
		}
		r.peerLock.Lock()
		peer := r.peer
		r.peerLock.Unlock()
		if peer.IsValid() {
			sequence++
			if _, err = r.local.WriteToUDPAddrPort(r.auth.sealDNS(dnsReply, sequence, packet[:n]), peer); err != nil {
				return
			}
		}
	}
}

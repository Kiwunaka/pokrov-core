// Adapted from cacggghp/vk-turn-proxy v1.8.3 (GPL-3.0).
package vk

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/turn/v5"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type tunnelSession struct {
	raw   net.Conn
	turn  *turn.Client
	relay net.PacketConn
	dtls  *dtls.Conn
	kcp   *kcp.UDPSession
	mux   *smux.Session
	once  sync.Once
}

func (s *tunnelSession) Close() {
	s.once.Do(func() {
		if s.mux != nil {
			s.mux.Close()
		}
		if s.kcp != nil {
			s.kcp.Close()
		}
		if s.dtls != nil {
			s.dtls.Close()
		}
		if s.relay != nil {
			s.relay.Close()
		}
		if s.turn != nil {
			s.turn.Close()
		}
		if s.raw != nil {
			s.raw.Close()
		}
	})
}

func (h *Outbound) connect(ctx context.Context) (_ *tunnelSession, err error) {
	user, password, address, err := h.credentials(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := h.dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(address))
	if err != nil {
		return nil, errors.New("VK TURN connection failed")
	}
	s := &tunnelSession{raw: raw}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { raw.Close(); close(closed) })
	stopped := false
	defer func() {
		if !stopped && !stop() {
			<-closed
		}
	}()
	// The protected dialer has already resolved the TURN hostname. Pion only
	// receives this numeric endpoint, so it cannot perform an unprotected DNS lookup.
	endpoint := raw.RemoteAddr().String()
	s.turn, err = turn.NewClient(&turn.ClientConfig{STUNServerAddr: endpoint, TURNServerAddr: endpoint, Conn: turn.NewSTUNConn(raw), Username: user, Password: password, RequestedAddressFamily: turn.RequestedAddressFamilyIPv4})
	if err != nil {
		return nil, errors.New("VK TURN client unavailable")
	}
	if err = s.turn.Listen(); err != nil {
		return nil, errors.New("VK TURN listener failed")
	}
	s.relay, err = s.turn.Allocate()
	if err != nil {
		return nil, errors.New("VK TURN relay allocation failed")
	}
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, errors.New("VK transport certificate unavailable")
	}
	// This is only the untrusted outer carrier. The VLESS caller must verify
	// the server using REALITY or TLS before sending subscription credentials.
	s.dtls, err = dtls.ClientWithOptions(&relayPacketConn{PacketConn: s.relay, peer: h.peer}, h.peer,
		dtls.WithCertificates(certificate), dtls.WithInsecureSkipVerify(true),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.OnlySendCIDGenerator()))
	if err != nil {
		return nil, errors.New("VK transport handshake unavailable")
	}
	handshake, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = s.dtls.HandshakeContext(handshake)
	cancel()
	if err != nil {
		return nil, errors.New("VK transport handshake failed")
	}
	block, err := kcp.NewNoneBlockCrypt(nil)
	if err != nil {
		return nil, err
	}
	s.kcp, err = kcp.NewConn2(h.peer, block, 0, 0, &dtlsPacketConn{Conn: s.dtls})
	if err != nil {
		return nil, errors.New("VK transport stream unavailable")
	}
	s.kcp.SetNoDelay(1, 20, 2, 1)
	s.kcp.SetWindowSize(256, 256)
	s.kcp.SetMtu(1200)
	s.kcp.SetACKNoDelay(true)
	config := smux.DefaultConfig()
	config.MaxReceiveBuffer = 4 << 20
	config.MaxStreamBuffer = 1 << 20
	config.KeepAliveInterval = 10 * time.Second
	config.KeepAliveTimeout = 30 * time.Second
	s.mux, err = smux.Client(s.kcp, config)
	if err != nil {
		return nil, errors.New("VK transport session unavailable")
	}
	stopped = true
	if !stop() {
		<-closed
		return nil, ctx.Err()
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

type relayPacketConn struct {
	net.PacketConn
	peer *net.UDPAddr
}

func (c *relayPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, c.peer)
}
func (c *relayPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(p)
		if err != nil || from.String() == c.peer.String() {
			return n, from, err
		}
	}
}

type dtlsPacketConn struct{ net.Conn }

func (c *dtlsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}
func (c *dtlsPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

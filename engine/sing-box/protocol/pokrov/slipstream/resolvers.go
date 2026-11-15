package slipstream

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func (h *Outbound) resolverPool() []netip.AddrPort {
	pool := append([]netip.AddrPort(nil), h.resolvers...)
	add := func(address netip.AddrPort) {
		if len(pool) >= maxResolvers {
			return
		}
		for _, previous := range pool {
			if previous == address {
				return
			}
		}
		pool = append(pool, address)
	}
	primary := netip.MustParseAddrPort("77.88.8.8:53")
	secondary := netip.MustParseAddrPort("77.88.8.1:53")
	for _, address := range h.resolvers {
		if address == primary || address == secondary {
			add(primary)
			add(secondary)
		}
	}
	if manager := service.FromContext[adapter.NetworkManager](h.ctx); manager != nil {
		if network := manager.DefaultNetworkInterface(); network != nil {
			for _, raw := range interfaceDNSServers(network) {
				switch raw {
				case "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4":
					continue
				}
				address, err := netip.ParseAddr(raw)
				if err == nil && address.Is4() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() {
					add(netip.AddrPortFrom(address, 53))
				}
			}
		}
	}
	return pool
}

func (h *Outbound) openResolvers(ctx context.Context) ([]net.Conn, error) {
	type result struct {
		connection net.Conn
		elapsed    time.Duration
	}
	pool := h.resolverPool()
	results := make(chan result, len(pool))
	for _, address := range pool {
		go func() {
			started := time.Now()
			connection, err := h.dialer.DialContext(ctx, N.NetworkUDP, M.SocksaddrFromNetIP(address))
			if err == nil {
				stop := context.AfterFunc(ctx, func() { connection.Close() })
				err = probeResolver(ctx, connection, h.domain)
				stop()
				if err != nil {
					// Some ISP resolvers forward tunnel TXT packets but suppress
					// the negative A reply. Let pinned QUIC validate that path.
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						connection.Close()
						connection = nil
					}
				}
			}
			results <- result{connection, time.Since(started)}
		}()
	}
	var ready []result
	for range pool {
		if reply := <-results; reply.connection != nil {
			ready = append(ready, reply)
		}
	}
	if ctx.Err() != nil {
		for _, reply := range ready {
			reply.connection.Close()
		}
		return nil, ctx.Err()
	}
	if len(ready) == 0 {
		return nil, errors.New("no DNS resolver answered the tunnel query")
	}
	sort.SliceStable(ready, func(i, j int) bool { return ready[i].elapsed < ready[j].elapsed })
	connections := make([]net.Conn, len(ready))
	for index, reply := range ready {
		connections[index] = reply.connection
	}
	return connections, nil
}

func probeResolver(ctx context.Context, connection net.Conn, domain string) error {
	deadline := time.Now().Add(2 * time.Second)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	defer connection.SetDeadline(time.Time{})
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	query := new(dns.Msg)
	query.SetQuestion("p-"+hex.EncodeToString(nonce[:])+"."+domain+".", dns.TypeA)
	query.SetEdns0(1232, false)
	packet, err := query.Pack()
	if err != nil {
		return err
	}
	if _, err = connection.Write(packet); err != nil {
		return err
	}
	buffer := make([]byte, 4096)
	for {
		size, err := connection.Read(buffer)
		if err != nil {
			return err
		}
		var reply dns.Msg
		if reply.Unpack(buffer[:size]) == nil && reply.Response && reply.Id == query.Id &&
			len(reply.Question) == 1 && strings.EqualFold(reply.Question[0].Name, query.Question[0].Name) &&
			reply.Question[0].Qtype == dns.TypeA {
			if reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError {
				return nil
			}
			return errors.New("DNS resolver rejected the tunnel query")
		}
	}
}

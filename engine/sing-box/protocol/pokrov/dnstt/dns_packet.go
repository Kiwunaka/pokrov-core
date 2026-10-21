package dnstt

// DNSTT packet framing/polling follows github.com/mahsanet/dnstt/client/dns.go
// (0ad0213669c6, CC0-1.0; see LICENSE.CC0). The local loop owns its socket and
// goroutines: upstream's sendLoop has no Close path and keeps polling forever.

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/mahsanet/dnstt/dns"
	"github.com/mahsanet/dnstt/turbotunnel"
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type dnsPacketConn struct {
	*turbotunnel.QueuePacketConn
	transport net.PacketConn
	addr      net.Addr
	domain    dns.Name
	clientID  turbotunnel.ClientID
	poll      chan struct{}
	done      chan struct{}
	workers   sync.WaitGroup
	once      sync.Once
}

func newDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name) *dnsPacketConn {
	id := turbotunnel.NewClientID()
	c := &dnsPacketConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(id, 0),
		transport:       transport, addr: addr, domain: domain, clientID: id,
		poll: make(chan struct{}, 16), done: make(chan struct{}),
	}
	c.workers.Add(2)
	go func() { defer c.workers.Done(); defer c.stop(); c.recvLoop() }()
	go func() { defer c.workers.Done(); defer c.stop(); c.sendLoop() }()
	return c
}

func (c *dnsPacketConn) stop() {
	c.once.Do(func() {
		close(c.done)
		c.transport.Close()
		c.QueuePacketConn.Close()
	})
}

func (c *dnsPacketConn) Close() error {
	c.stop()
	c.workers.Wait()
	return nil
}

func (c *dnsPacketConn) recvLoop() {
	var buf [4096]byte
	for {
		n, _, err := c.transport.ReadFrom(buf[:])
		if err != nil {
			return
		}
		response, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil || response.Flags&0x800f != 0x8000 || len(response.Answer) != 1 {
			continue
		}
		answer := response.Answer[0]
		if _, ok := answer.Name.TrimSuffix(c.domain); !ok || answer.Type != dns.RRTypeTXT {
			continue
		}
		payload, err := dns.DecodeRDataTXT(answer.Data)
		if err != nil {
			continue
		}
		for len(payload) >= 2 {
			size := int(binary.BigEndian.Uint16(payload))
			payload = payload[2:]
			if size > len(payload) {
				break
			}
			c.QueueIncoming(payload[:size], c.addr)
			payload = payload[size:]
			select {
			case c.poll <- struct{}{}:
			default:
			}
		}
	}
}

func (c *dnsPacketConn) sendLoop() {
	delay := 500 * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	outgoing := c.OutgoingQueue(c.addr)
	for {
		var packet []byte
		timedPoll := false
		select {
		case <-c.done:
			return
		case packet = <-outgoing:
		default:
			select {
			case <-c.done:
				return
			case packet = <-outgoing:
			case <-c.poll:
			case <-timer.C:
				timedPoll = true
			}
		}
		if len(packet) > 0 {
			select {
			case <-c.poll:
			default:
			}
		}
		if timedPoll {
			delay = min(2*delay, 10*time.Second)
		} else {
			delay = 500 * time.Millisecond
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
		query, err := encodeQuery(packet, c.clientID, c.domain)
		if err != nil {
			return
		}
		if _, err = c.transport.WriteTo(query, c.addr); err != nil {
			return
		}
	}
}

func encodeQuery(packet []byte, id turbotunnel.ClientID, domain dns.Name) ([]byte, error) {
	if len(packet) >= 224 {
		return nil, errors.New("dnstt packet exceeds query capacity")
	}
	padding := 3
	if len(packet) == 0 {
		padding = 8
	}
	payload := make([]byte, len(id)+1+padding)
	copy(payload, id[:])
	payload[len(id)] = byte(224 + padding)
	if _, err := rand.Read(payload[len(id)+1:]); err != nil {
		return nil, err
	}
	if len(packet) > 0 {
		payload = append(payload, byte(len(packet)))
		payload = append(payload, packet...)
	}
	encoded := bytes.ToLower([]byte(base32Encoding.EncodeToString(payload)))
	var labels [][]byte
	for len(encoded) > 0 {
		size := min(63, len(encoded))
		labels = append(labels, encoded[:size])
		encoded = encoded[size:]
	}
	labels = append(labels, domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return nil, err
	}
	var queryID [2]byte
	if _, err := rand.Read(queryID[:]); err != nil {
		return nil, err
	}
	query := dns.Message{
		ID: binary.BigEndian.Uint16(queryID[:]), Flags: 0x0100,
		Question:   []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
		Additional: []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096}},
	}
	return query.WireFormat()
}

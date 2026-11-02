package slipstream

import (
	"bytes"
	"context"
	"crypto/hmac"
	"io"
	"net"
	"testing"
	"time"
)

func TestLocalAuthRejectsWrongChildBeforeApplicationData(t *testing.T) {
	auth, err := newLocalAuth()
	if err != nil {
		t.Fatal(err)
	}
	wrong := auth
	wrong.key[0] ^= 1
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			observed <- nil
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		var hello [56]byte
		io.ReadFull(conn, hello[:])
		var childNonce [32]byte
		childNonce[0] = 1
		conn.Write(append(childNonce[:], wrong.mac(childProof, hello[24:], childNonce[:])...))
		rest, _ := io.ReadAll(conn)
		observed <- append(hello[:], rest...)
	}()
	session := &tunnelSession{address: listener.Addr().String(), auth: auth, done: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := session.dial(ctx); err == nil {
		conn.Close()
		t.Fatal("wrong child was admitted before the caller could write VLESS")
	}
	if message := <-observed; len(message) != 56 || string(message[:8]) != tcpMagic {
		t.Fatal("wrong child received bytes beyond the public authentication challenge")
	}
}

func TestLocalAuthMutualProofAndCancellation(t *testing.T) {
	auth, err := newLocalAuth()
	if err != nil {
		t.Fatal(err)
	}
	parent, child := net.Pipe()
	defer parent.Close()
	defer child.Close()
	verified := make(chan bool, 1)
	go func() {
		var hello [56]byte
		if _, err := io.ReadFull(child, hello[:]); err != nil {
			verified <- false
			return
		}
		var nonce [32]byte
		nonce[0] = 2
		child.Write(append(nonce[:], auth.mac(childProof, hello[24:], nonce[:])...))
		var proof [32]byte
		_, err := io.ReadFull(child, proof[:])
		verified <- err == nil && hmac.Equal(proof[:], auth.mac(parentProof, hello[24:], nonce[:]))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := auth.authenticate(ctx, parent); err != nil || !<-verified {
		t.Fatal("mutual proof failed:", err)
	}
	stalled, peer := net.Pipe()
	defer stalled.Close()
	defer peer.Close()
	ctx, cancel = context.WithCancel(context.Background())
	read := make(chan struct{})
	go func() { io.CopyN(io.Discard, peer, 56); close(read) }()
	done := make(chan error, 1)
	go func() { done <- auth.authenticate(ctx, stalled) }()
	<-read
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled authentication succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled authentication retained the local socket")
	}
}

func TestDNSRelayRejectsFirstSenderForgeryReplayAndOldGeneration(t *testing.T) {
	auth, err := newLocalAuth()
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	remote, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newDNSRelay(remote, auth)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	legitimate, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer legitimate.Close()
	attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	address := relay.local.LocalAddr().(*net.UDPAddr)
	query := []byte("DNS query from the child")
	frame := auth.sealDNS(dnsQuery, 1, query)
	attacker.WriteToUDP([]byte("first unauthenticated sender"), address)
	attacker.WriteToUDP(frame, address)
	relay.setPeer(legitimate.LocalAddr().(*net.UDPAddr).AddrPort())
	legitimate.WriteToUDP(frame, address)
	server.SetDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 4096)
	n, from, err := server.ReadFromUDP(buffer)
	if err != nil || !bytes.Equal(buffer[:n], query) {
		t.Fatal("the first foreign sender captured or poisoned the relay:", err)
	}
	server.WriteToUDP([]byte("DNS reply"), from)
	legitimate.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = legitimate.ReadFromUDP(buffer)
	payload, sequence, valid := auth.openDNS(dnsReply, buffer[:n])
	if err != nil || !valid || sequence != 1 || string(payload) != "DNS reply" {
		t.Fatal("reply was not authenticated to the child:", err)
	}
	legitimate.WriteToUDP(frame, address)                            // Replay.
	legitimate.WriteToUDP(auth.sealDNS(dnsReply, 2, query), address) // Reflection.
	old := auth
	old.generation[0] ^= 1
	legitimate.WriteToUDP(old.sealDNS(dnsQuery, 2, query), address)
	wrong := auth
	wrong.key[0] ^= 1
	legitimate.WriteToUDP(wrong.sealDNS(dnsQuery, 2, query), address)
	attacker.WriteToUDP(auth.sealDNS(dnsQuery, 2, query), address) // Even a captured frame cannot repin the port.
	legitimate.WriteToUDP(auth.sealDNS(dnsQuery, 2, []byte("next DNS query")), address)
	n, _, err = server.ReadFromUDP(buffer)
	if err != nil || string(buffer[:n]) != "next DNS query" {
		t.Fatal("forged, replayed or old-generation DNS crossed the relay:", err)
	}
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := server.ReadFromUDP(buffer); err == nil {
		t.Fatal("rejected DNS was forwarded after the legitimate packet")
	}
}

package slipstream

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

const (
	bootstrapMagic = "PKRVIPC1"
	readyMagic     = "PKRVRDY1"
	tcpMagic       = "PKRVTCP1"
	dnsMagic       = "PKRVDNS1"
	dnsFrameSize   = 8 + 16 + 8 + sha256.Size
	childProof     = "pokrov/slipstream/local/v1/tcp/child\x00"
	parentProof    = "pokrov/slipstream/local/v1/tcp/parent\x00"
	dnsQuery       = "pokrov/slipstream/local/v1/dns/query\x00"
	dnsReply       = "pokrov/slipstream/local/v1/dns/reply\x00"
)

// Each native process receives a fresh key and generation only over its private
// stdin pipe. Neither is a CLI argument, environment variable or disk file.
type localAuth struct {
	key        [32]byte
	generation [16]byte
}

func newLocalAuth() (localAuth, error) {
	var auth localAuth
	if _, err := rand.Read(auth.key[:]); err != nil {
		return auth, err
	}
	_, err := rand.Read(auth.generation[:])
	return auth, err
}

func (a *localAuth) bootstrap() []byte {
	message := append([]byte(bootstrapMagic), a.key[:]...)
	return append(message, a.generation[:]...)
}

func (a *localAuth) mac(domain string, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, a.key[:])
	mac.Write([]byte(domain))
	mac.Write(a.generation[:])
	for _, part := range parts {
		mac.Write(part)
	}
	return mac.Sum(nil)
}

func (a *localAuth) authenticate(ctx context.Context, conn net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	hello := append([]byte(tcpMagic), a.generation[:]...)
	hello = append(hello, nonce[:]...)
	if _, err := io.Copy(conn, bytes.NewReader(hello)); err != nil {
		return err
	}
	var reply [64]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if !hmac.Equal(reply[32:], a.mac(childProof, nonce[:], reply[:32])) {
		return errors.New("slipstream local authentication failed")
	}
	if _, err := io.Copy(conn, bytes.NewReader(a.mac(parentProof, nonce[:], reply[:32]))); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}

func (a *localAuth) parseReady(message []byte) (string, netip.AddrPort, error) {
	if len(message) != 28 || string(message[:8]) != readyMagic || !bytes.Equal(message[8:24], a.generation[:]) {
		return "", netip.AddrPort{}, errors.New("slipstream native client has an incompatible local protocol")
	}
	tcpPort, udpPort := binary.BigEndian.Uint16(message[24:26]), binary.BigEndian.Uint16(message[26:28])
	if tcpPort == 0 || udpPort == 0 {
		return "", netip.AddrPort{}, errors.New("slipstream native client returned an invalid local port")
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	return netip.AddrPortFrom(loopback, tcpPort).String(), netip.AddrPortFrom(loopback, udpPort), nil
}

func (a *localAuth) sealDNS(domain string, sequence uint64, payload []byte) []byte {
	message := make([]byte, 32, len(payload)+dnsFrameSize)
	copy(message, dnsMagic)
	copy(message[8:], a.generation[:])
	binary.BigEndian.PutUint64(message[24:], sequence)
	message = append(message, payload...)
	return append(message, a.mac(domain, message)...)
}

func (a *localAuth) openDNS(domain string, message []byte) ([]byte, uint64, bool) {
	if len(message) <= dnsFrameSize || string(message[:8]) != dnsMagic || !bytes.Equal(message[8:24], a.generation[:]) {
		return nil, 0, false
	}
	end := len(message) - sha256.Size
	if !hmac.Equal(message[end:], a.mac(domain, message[:end])) {
		return nil, 0, false
	}
	sequence := binary.BigEndian.Uint64(message[24:32])
	return message[32:end], sequence, sequence != 0
}

// A small replay window retains normal reordered UDP packets on loopback.
type replayWindow struct {
	highest uint64
	bitmap  uint64
}

func (w *replayWindow) accept(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	if sequence > w.highest {
		shift := sequence - w.highest
		w.bitmap = w.bitmap<<shift | 1
		w.highest = sequence
		return true
	}
	distance := w.highest - sequence
	if distance >= 64 || w.bitmap&(uint64(1)<<distance) != 0 {
		return false
	}
	w.bitmap |= uint64(1) << distance
	return true
}

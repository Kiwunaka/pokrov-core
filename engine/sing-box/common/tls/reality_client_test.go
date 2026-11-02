//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

func TestRealityClientHelloRecordFragment(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, config string
		fragmented   bool
	}{
		{"omitted retains workaround", `{}`, true},
		{"explicit false keeps SNI contiguous", `{"record_fragment":false}`, false},
		{"explicit true", `{"record_fragment":true}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var options option.OutboundTLSOptions
			if err := json.Unmarshal([]byte(test.config), &options); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(options)
			if err != nil || !bytes.Equal(encoded, []byte(test.config)) {
				t.Fatal("record_fragment choice did not survive JSON round trip")
			}
			options.Enabled = true
			options.ServerName = "bridge.example.test"
			options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
			options.Reality = &option.OutboundRealityOptions{
				Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
			}
			config, err := NewRealityClient(context.Background(), logger.NOP(), "bridge.example.test", options)
			if err != nil {
				t.Fatal(err)
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			client.SetDeadline(time.Now().Add(2 * time.Second))
			server.SetDeadline(time.Now().Add(2 * time.Second))
			hellos := make(chan []byte, 1)
			go func() {
				data := make([]byte, 65535)
				n, _ := server.Read(data)
				server.Close()
				hellos <- data[:n]
			}()
			if _, err := ClientHandshake(context.Background(), client, config); err == nil {
				t.Fatal("synthetic peer must not pass server verification")
			}
			data := <-hellos
			records := 0
			var hello []byte
			for len(data) > 0 {
				if len(data) < 5 || data[0] != 22 {
					t.Fatal("invalid ClientHello record")
				}
				size := 5 + int(binary.BigEndian.Uint16(data[3:5]))
				if size > len(data) {
					t.Fatal("incomplete ClientHello record")
				}
				records++
				hello = append(hello, data[5:size]...)
				data = data[size:]
			}
			if records == 0 || (records > 1) != test.fragmented {
				t.Fatalf("ClientHello record count = %d, fragmented = %v", records, test.fragmented)
			}
			assertRealityClientHello(t, hello, key)
		})
	}
}

// Independently parse the emitted bytes and decrypt the REALITY session ID as
// XTLS/REALITY tls.go does. This catches version, AEAD and hybrid-share changes.
func assertRealityClientHello(t *testing.T, hello []byte, key *ecdh.PrivateKey) {
	t.Helper()
	if len(hello) < 71 || hello[0] != 1 || hello[38] != 32 {
		t.Fatal("invalid REALITY ClientHello")
	}
	message := cryptobyte.String(hello[71:])
	var suites, compression, extensions cryptobyte.String
	if !message.ReadUint16LengthPrefixed(&suites) || !message.ReadUint8LengthPrefixed(&compression) ||
		!message.ReadUint16LengthPrefixed(&extensions) || !message.Empty() {
		t.Fatal("invalid ClientHello extension framing")
	}
	var classical, hybrid []byte
	for !extensions.Empty() {
		var kind uint16
		var extension cryptobyte.String
		if !extensions.ReadUint16(&kind) || !extensions.ReadUint16LengthPrefixed(&extension) {
			t.Fatal("invalid TLS extension")
		}
		if kind != 51 {
			continue
		}
		var shares cryptobyte.String
		if !extension.ReadUint16LengthPrefixed(&shares) {
			t.Fatal("invalid key share vector")
		}
		for !shares.Empty() {
			var group uint16
			var share cryptobyte.String
			if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&share) {
				t.Fatal("invalid key share")
			}
			if group == uint16(utls.X25519MLKEM768) {
				if classical != nil || len(share) != mlkem.EncapsulationKeySize768+32 {
					t.Fatal("hybrid share is malformed or follows X25519")
				}
				hybrid = share[mlkem.EncapsulationKeySize768:]
			} else if group == uint16(utls.X25519) {
				classical = share
			}
		}
	}
	if hybrid == nil {
		t.Fatal("REALITY ClientHello omitted X25519MLKEM768")
	}
	if classical == nil {
		classical = hybrid
	}
	peer, err := ecdh.X25519().NewPublicKey(classical)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	authKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, hello[6:26], []byte("REALITY")), authKey); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	associated := bytes.Clone(hello)
	clear(associated[39:71])
	plain, err := aead.Open(nil, hello[26:38], hello[39:71], associated)
	if err != nil || !bytes.Equal(plain[:4], []byte{26, 6, 27, 0}) {
		t.Fatalf("REALITY version/session authentication mismatch: %v", err)
	}
}

func TestRealityRejectsFingerprintWithoutHybridKeyShare(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewRealityClient(context.Background(), logger.NOP(), "bridge.example.test", option.OutboundTLSOptions{
		Enabled: true, ServerName: "bridge.example.test",
		UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "safari"},
		Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	if _, err := ClientHandshake(context.Background(), client, config); err == nil || !strings.Contains(err.Error(), "X25519MLKEM768") {
		t.Fatalf("non-hybrid fingerprint was not rejected before IO: %v", err)
	}
}

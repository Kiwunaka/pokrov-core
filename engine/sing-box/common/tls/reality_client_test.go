//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
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
			for len(data) > 0 {
				if len(data) < 5 || data[0] != 22 {
					t.Fatal("invalid ClientHello record")
				}
				size := 5 + int(binary.BigEndian.Uint16(data[3:5]))
				if size > len(data) {
					t.Fatal("incomplete ClientHello record")
				}
				records++
				data = data[size:]
			}
			if records == 0 || (records > 1) != test.fragmented {
				t.Fatalf("ClientHello record count = %d, fragmented = %v", records, test.fragmented)
			}
		})
	}
}

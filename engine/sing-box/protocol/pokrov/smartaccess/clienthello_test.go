package smartaccess

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type clientHelloRelay struct {
	N.Dialer
	calls       int
	destination M.Socksaddr
}

func (d *clientHelloRelay) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	d.calls++
	d.destination = destination
	local, peer := net.Pipe()
	_ = peer.Close()
	return local, nil
}

type clientHelloManager struct {
	adapter.ConnectionManager
	expected, forwarded []byte
	destination         M.Socksaddr
}

func (m *clientHelloManager) NewConnection(ctx context.Context, dialer N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	remote, err := dialer.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err == nil {
		m.forwarded = make([]byte, len(m.expected))
		_, err = io.ReadFull(conn, m.forwarded)
		m.destination = metadata.Destination
		_ = remote.Close()
	}
	onClose(err)
}

// A syntactically valid ClientHello with an opaque ECH extension before SNI,
// as Chromium's shuffled extension order permits. No GREASE guess or TLS rewrite.
func clientHelloRecord(ech bool, names ...string) []byte {
	var extensions []byte
	if ech {
		extensions = append(extensions, 0xfe, 0x0d, 0, 1, 0)
	}
	for _, name := range names {
		entry := append([]byte{0, byte(len(name) >> 8), byte(len(name))}, name...)
		extension := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
		extensions = append(extensions, 0, 0, byte(len(extension)>>8), byte(len(extension)))
		extensions = append(extensions, extension...)
	}
	body := make([]byte, 34)
	body[0], body[1] = 3, 3
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := append([]byte{22, 3, 1, 0, 0}, handshake...)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	return record
}

func TestExternalECHKeepsExactOuterSNIAndPinnedRelay(t *testing.T) {
	for _, test := range []struct {
		name                   string
		external, ech, allowed bool
		names                  []string
	}{
		{"owned_visible_sni", false, false, true, []string{"service.test"}},
		{"owned_ech", false, true, false, []string{"service.test"}},
		{"external_ech", true, true, true, []string{"service.test"}},
		{"external_wrong_outer_sni", true, true, false, []string{"other.test"}},
		{"external_no_outer_sni", true, true, false, nil},
		{"external_duplicate_outer_sni", true, true, false, []string{"service.test", "service.test"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := clientHelloRecord(test.ech, test.names...)
			manager := &clientHelloManager{expected: raw}
			ctx := service.ContextWith[adapter.ConnectionManager](context.Background(), manager)
			now := time.Now().UTC().Truncate(time.Second)
			options := option.PokrovSmartAccessOutboundOptions{
				LeaseID: "0123456789abcdef0123456789abcdef", IssuedAt: now.Format(timeLayout),
				NewFlowsUntil: now.Add(time.Minute).Format(timeLayout), ActiveFlowsUntil: now.Add(2 * time.Minute).Format(timeLayout),
				RelayAddresses: []string{"1.1.1.1"}, Domains: []option.PokrovSmartAccessDomain{{Name: "service.test", Match: "exact"}},
				ExternalECHOuterSNI: test.external, MaxNewConnectionsPerMinute: 10, MaxConcurrentConnections: 2,
			}
			rawMember, err := NewOutbound(ctx, nil, nil, "smart", options)
			if err != nil {
				t.Fatal(err)
			}
			member := rawMember.(*Outbound)
			defer member.Close()
			relay := &clientHelloRelay{}
			member.dialer = relay
			client, accepted := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go member.NewConnection(ctx, accepted, adapter.InboundContext{Destination: M.Socksaddr{Fqdn: "service.test", Port: 443}}, func(err error) { done <- err })
			_, _ = client.Write(raw)
			select {
			case err = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("ClientHello admission did not finish")
			}
			if test.allowed {
				if err != nil || member.lease.probeFailure != nil || relay.calls != 1 || relay.destination.String() != "1.1.1.1:443" ||
					manager.destination.Fqdn != "service.test" || !bytes.Equal(raw, manager.forwarded) {
					t.Fatal("authorized outer SNI did not retain the pinned relay and exact TLS bytes")
				}
			} else if err == nil || relay.calls != 0 || manager.forwarded != nil {
				t.Fatal("unsupported ClientHello reached the relay")
			}
			if test.ech && !test.external && member.lease.probeFailure == nil {
				t.Fatal("owned ECH rejection lost its readiness failure")
			}
			if test.name == "external_ech" {
				options.Domains[0].Match = "suffix"
				if _, err := NewOutbound(ctx, nil, nil, "invalid", options); err == nil {
					t.Fatal("external ECH accepted a suffix authority")
				}
			}
		})
	}
}

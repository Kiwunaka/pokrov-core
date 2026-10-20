package v2rayapi

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type statsTestOutbound struct{ adapter.Outbound }

func (statsTestOutbound) Tag() string { return "direct" }

type statsTestConn struct {
	net.Conn
	reader io.Reader
}

func (c *statsTestConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (*statsTestConn) Write(p []byte) (int, error)  { return len(p), nil }
func (*statsTestConn) Close() error                 { return nil }

type statsTestPacketConn struct{ N.PacketConn }

func (*statsTestPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	_, err := buffer.WriteString("uplink")
	return M.Socksaddr{}, err
}

func (*statsTestPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (*statsTestPacketConn) Close() error { return nil }

func transferUserTraffic(t *testing.T, service *StatsService, user string) {
	t.Helper()
	metadata := adapter.InboundContext{User: user}
	conn := service.RoutedConnection(context.Background(),
		&statsTestConn{reader: strings.NewReader("uplink")}, metadata, nil, statsTestOutbound{})
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("downlink")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	packet := service.RoutedPacketConnection(context.Background(),
		&statsTestPacketConn{}, metadata, nil, statsTestOutbound{})
	buffer := buf.New()
	if _, err := packet.ReadPacket(buffer); err != nil {
		t.Fatal(err)
	}
	buffer.Release()
	if err := packet.WritePacket(buf.As([]byte("downlink")), M.Socksaddr{}); err != nil {
		t.Fatal(err)
	}
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertUserTraffic(t *testing.T, service *StatsService, users ...string) {
	t.Helper()
	// Closed TCP and UDP streams retain their cumulative totals. Reading the
	// collection twice without reset must not consume the collector's baseline.
	for range 2 {
		response, err := service.QueryStats(context.Background(), &QueryStatsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[string]int64)
		for _, stat := range response.Stat {
			got[stat.Name] = stat.Value
		}
		if len(got) != len(users)*2 {
			t.Fatalf("unexpected counters: %v", got)
		}
		for _, user := range users {
			if got["user>>>"+user+">>>traffic>>>uplink"] != 12 ||
				got["user>>>"+user+">>>traffic>>>downlink"] != 16 {
				t.Fatalf("incorrect TCP/UDP totals: %v", got)
			}
		}
	}
}

func TestAllUsersTracksDynamicTCPAndUDP(t *testing.T) {
	service := NewStatsService(option.V2RayStatsServiceOptions{Enabled: true, AllUsers: true})
	transferUserTraffic(t, service, "first-user")
	// A user first seen after service creation needs no allowlist update.
	transferUserTraffic(t, service, "later-user")
	transferUserTraffic(t, service, "")
	assertUserTraffic(t, service, "first-user", "later-user")
}

func TestUserStatsDefaultKeepsAllowlist(t *testing.T) {
	service := NewStatsService(option.V2RayStatsServiceOptions{Enabled: true, Users: []string{"selected-user"}})
	transferUserTraffic(t, service, "selected-user")
	transferUserTraffic(t, service, "unlisted-user")
	transferUserTraffic(t, service, "")
	assertUserTraffic(t, service, "selected-user")
}

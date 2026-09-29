package trafficcontrol

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type testOutbound struct{ adapter.Outbound }

func (testOutbound) Tag() string  { return "candidate" }
func (testOutbound) Type() string { return "direct" }

type testOutboundManager struct{ adapter.OutboundManager }

func (testOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return testOutbound{}, tag == "candidate"
}

func TestConnectionEventsAndOutboundUsageSurviveHistoryClear(t *testing.T) {
	m := NewManager(testOutboundManager{})
	if err := m.Start(adapter.StartStateInitialize); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	events, done, err := m.SubscribeEvents()
	if err != nil {
		t.Fatal(err)
	}
	defer m.UnSubscribeEvents(events)
	client, peer := net.Pipe()
	defer peer.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	conn := m.RoutedConnection(context.Background(), client, adapter.InboundContext{}, nil, testOutbound{})
	defer conn.Close()
	peerResult := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte("req"))
		if err == nil {
			_, err = io.CopyN(io.Discard, peer, 5)
		}
		peerResult <- err
	}()
	if _, err = io.ReadFull(conn, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err = <-peerResult; err != nil {
		t.Fatal(err)
	}
	checkUsage := func() {
		t.Helper()
		if upload, download := m.OutboundUsage("candidate"); upload != 3 || download != 5 {
			t.Fatalf("lost outbound traffic: upload=%d download=%d", upload, download)
		}
	}
	checkUsage()
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []ConnectionEventType{ConnectionEventNew, ConnectionEventClosed} {
		select {
		case event := <-events:
			if event.Type != eventType || event.Metadata.Outbound != "candidate" {
				t.Fatal("connection event lost its outbound or lifecycle state")
			}
		case <-time.After(time.Second):
			t.Fatal("connection event did not settle")
		}
	}
	checkUsage()
	m.Clear()
	checkUsage()
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed traffic manager left its subscriber alive")
	}
}

package device

import (
	"bytes"
	"errors"
	"testing"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/pokrov"
)

type noiseRecordingBind struct {
	conn.Bind
	packets       [][]byte
	withoutModify bool
	err           error
}

func (b *noiseRecordingBind) Send(packets [][]byte, _ conn.Endpoint, offset int) error {
	for _, packet := range packets {
		b.packets = append(b.packets, bytes.Clone(packet[offset:]))
	}
	return b.err
}

func (b *noiseRecordingBind) SendWithoutModify(packets [][]byte, endpoint conn.Endpoint, offset int) error {
	b.withoutModify = true
	return b.Send(packets, endpoint, offset)
}

func newNoiseTestPeer(t *testing.T, bind *noiseRecordingBind) *Peer {
	t.Helper()
	endpoint, err := conn.NewStdNetBind(nil).ParseEndpoint("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	device := &Device{closed: make(chan struct{}), stopCh: make(chan int, 1)}
	device.net.bind = bind
	peer := &Peer{device: device}
	peer.endpoint.val = endpoint
	peer.isRunning.Store(true)
	return peer
}

func TestPokrovNoisePreservesPacketAndPropagatesSendFailure(t *testing.T) {
	bind := &noiseRecordingBind{}
	peer := newNoiseTestPeer(t, bind)
	payload := []byte("noise-payload")
	if err := peer.customSend([]byte{0x42}, payload, true); err != nil {
		t.Fatal(err)
	}
	if !bind.withoutModify || len(bind.packets) != 1 {
		t.Fatal("NoModify packet did not use the dedicated bind operation")
	}
	packet := bind.packets[0]
	header := []byte{0x42, 0, 0, 0, 1, 8}
	if len(packet) != len(header)+8+4+len(payload) || !bytes.HasPrefix(packet, header) || !bytes.HasSuffix(packet, payload) {
		t.Fatal("bind offset removed part of the configured Noise packet")
	}

	sendErr := errors.New("test bind send failure")
	bind.err = sendErr
	bind.packets = nil
	peer.device.HNoise.FakePacket = pokrov.FakePacketOptions{
		Enabled: true,
		Count:   pokrov.Range{From: 2, To: 2},
		Size:    pokrov.Range{From: 20, To: 20},
	}
	if err := peer.sendNoise(); !errors.Is(err, sendErr) {
		t.Fatal("Noise send failure was lost")
	}
	if len(bind.packets) != 1 {
		t.Fatal("Noise continued sending after the bind failed")
	}
}

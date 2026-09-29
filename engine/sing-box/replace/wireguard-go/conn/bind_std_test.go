package conn

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestStdNetBindSendWithoutModify(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	bind := NewStdNetBind(nil)
	if _, _, err = bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	endpoint, err := bind.ParseEndpoint(receiver.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	bind.SetReservedForEndpoint(netip.MustParseAddrPort(receiver.LocalAddr().String()), [3]byte{7, 8, 9})
	for _, noModify := range []bool{true, false} {
		packet := []byte{0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 2, 3, 5}
		if noModify {
			err = bind.SendWithoutModify([][]byte{packet}, endpoint, 8)
		} else {
			err = bind.Send([][]byte{packet}, endpoint, 8)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 32)
		n, _, err := receiver.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{4, 1, 2, 3, 5}
		if !noModify {
			want = []byte{4, 7, 8, 9, 5}
		}
		if !bytes.Equal(buffer[:n], want) {
			t.Fatalf("reserved mutation mismatch for NoModify=%v", noModify)
		}
	}
}

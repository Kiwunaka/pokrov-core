package tls

import (
	"context"
	"net"
	"testing"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
)

func TestWrapClientHelloFragment(t *testing.T) {
	tests := []struct {
		name           string
		fragment       bool
		recordFragment bool
		wantWrapped    bool
	}{
		{name: "disabled", wantWrapped: false},
		{name: "packet fragmentation", fragment: true, wantWrapped: true},
		{name: "record fragmentation", recordFragment: true, wantWrapped: true},
		{name: "packet and record fragmentation", fragment: true, recordFragment: true, wantWrapped: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			wrappedConn := wrapClientHelloFragment(
				context.Background(),
				clientConn,
				test.fragment,
				test.recordFragment,
				0,
			)
			_, wrapped := wrappedConn.(*tf.Conn)
			if wrapped != test.wantWrapped {
				t.Fatalf("wrapped = %v, want %v", wrapped, test.wantWrapped)
			}
		})
	}
}

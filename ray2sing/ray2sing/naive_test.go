package ray2sing

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestNaiveQUICSelection(t *testing.T) {
	for _, test := range []struct {
		query string
		quic  bool
	}{
		{"", false},
		{"quic=false", false},
		{"quic=0", false},
		{"quic=true", true},
		{"quic=1", true},
	} {
		t.Run(test.query, func(t *testing.T) {
			outbound, err := NaiveSingbox("naive://test-user:test-password@proxy.example:443?" + test.query)
			if err != nil {
				t.Fatal(err)
			}
			options := outbound.Options.(*option.NaiveOutboundOptions)
			if options.QUIC != test.quic {
				t.Fatalf("QUIC = %v, want %v", options.QUIC, test.quic)
			}
		})
	}
}

package tls

import (
	"bytes"
	"testing"
)

func TestUnsafeConnectionStateHelloRetryRequest(t *testing.T) {
	for _, retry := range []bool{false, true} {
		name := "direct"
		if retry {
			name = "retry"
		}
		t.Run(name, func(t *testing.T) {
			clientConfig := testConfig.Clone()
			clientConfig.MinVersion = VersionTLS13
			clientConfig.CurvePreferences = []CurveID{X25519, CurveP256}
			serverConfig := clientConfig.Clone()
			if retry {
				serverConfig.CurvePreferences = []CurveID{CurveP256}
			}
			server, client, err := testHandshake(t, clientConfig, serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			for _, state := range []*ConnectionState{&server, &client} {
				converted := UnsafeFromConnectionState(state)
				if state.HelloRetryRequest != retry || converted.HelloRetryRequest != retry {
					t.Fatalf("HelloRetryRequest: native=%v converted=%v want=%v", state.HelloRetryRequest, converted.HelloRetryRequest, retry)
				}
				if converted.CurveID != UnsafeFromConnectionState(&client).CurveID || !converted.HandshakeComplete {
					t.Fatal("converted handshake state differs")
				}
				want, err := state.ExportKeyingMaterial("r12-layout-test", nil, 32)
				if err != nil {
					t.Fatal(err)
				}
				got, err := converted.ExportKeyingMaterial("r12-layout-test", nil, 32)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("converted exporter closure differs")
				}
				if UnsafeToConnectionState(converted) != state {
					t.Fatal("connection state round trip changed its address")
				}
			}
		})
	}
}

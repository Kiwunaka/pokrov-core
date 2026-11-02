package hcore

import "testing"

func TestUnauthenticatedGRPCEntryPointsAreClosed(t *testing.T) {
	if server, err := StartCoreGrpcServer("0.0.0.0:0"); err == nil || server != nil {
		t.Fatal("standalone Core control listener was admitted")
	}
	for _, mode := range []SetupMode{SetupMode_GRPC_BACKGROUND_INSECURE, SetupMode_GRPC_NORMAL_INSECURE} {
		if server, err := StartGrpcServerByMode("0.0.0.0:0", mode); err == nil || server != nil {
			t.Fatal("insecure Core setup mode was admitted")
		}
	}
}

func TestGetServerPublicKeyWithoutGRPCSetup(t *testing.T) {
	mu.Lock()
	previous := certpair
	certpair = nil
	mu.Unlock()
	t.Cleanup(func() { mu.Lock(); certpair = previous; mu.Unlock() })
	if key := GetGrpcServerPublicKey(); len(key) != 0 {
		t.Fatal("uninitialized server returned a public key")
	}
}

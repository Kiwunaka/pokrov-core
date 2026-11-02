package libbox

import "testing"

func TestPProfServerIsClosedInClientSDK(t *testing.T) {
	server := NewPProfServer(0)
	if err := server.Start(); err == nil {
		t.Fatal("client SDK opened a profiling listener")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

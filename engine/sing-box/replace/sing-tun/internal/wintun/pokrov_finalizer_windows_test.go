//go:build pokrov_wintun_test

package wintun

import "testing"

func TestPokrovFinalizerPassesAdapterHandle(t *testing.T) {
	probe := PokrovInstallFixtureProbe()
	closeAdapter(&Adapter{handle: probe.Handle})
	if probe.RealDLLLoaded() {
		t.Fatal("test unexpectedly loaded real Wintun")
	}
	if probe.CloseCalls() != 1 || probe.LastHandle() != probe.Handle {
		t.Fatalf("close callback: calls=%d handle=%#x; want 1 and %#x", probe.CloseCalls(), probe.LastHandle(), probe.Handle)
	}
}

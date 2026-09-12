//go:build pokrov_wintun_test

package tun

import (
	"github.com/sagernet/sing-tun/internal/wintun"
	"runtime/debug"
	"testing"
)

func TestPokrovFailedSessionClosesAdapterImmediately(t *testing.T) {
	previous := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previous)
	probe := wintun.PokrovInstallFixtureProbe()
	tunnel, err := New(Options{Name: "r12-c05-synthetic-callback"})
	if err == nil || tunnel != nil {
		t.Fatal("synthetic failed session was not rejected")
	}
	if probe.RealDLLLoaded() {
		t.Fatal("test unexpectedly loaded real Wintun")
	}
	if probe.CloseCalls() != 1 || probe.LastHandle() != probe.Handle {
		t.Fatalf("immediate cleanup: calls=%d handle=%#x; want 1 and %#x", probe.CloseCalls(), probe.LastHandle(), probe.Handle)
	}
}

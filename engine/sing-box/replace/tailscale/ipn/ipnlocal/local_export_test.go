package ipnlocal

import (
	"slices"
	"testing"

	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/netmap"
)

func TestExternalSSHHostKeysSurviveHostinfoRefresh(t *testing.T) {
	b := &LocalBackend{hostinfo: &tailcfg.Hostinfo{}}
	b.sshAtomicBool.Store(true)
	nativeSSH := b.ShouldRunSSH()
	keys := []string{"external-test-key"}
	b.SetExternalSSHHostKeys(keys)
	if !slices.Equal(b.hostinfo.SSH_HostKeys, keys) || b.ShouldRunSSH() {
		t.Fatal("external SSH host keys must be advertised without starting native SSH")
	}
	refresh := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.applyPrefsToHostinfoLocked(b.hostinfo, (&ipn.Prefs{}).View())
	}
	refresh()
	if !slices.Equal(b.hostinfo.SSH_HostKeys, keys) {
		t.Fatal("hostinfo refresh dropped external SSH host keys")
	}
	b.SetExternalSSHHostKeys(nil)
	refresh()
	if len(b.hostinfo.SSH_HostKeys) != 0 || b.ShouldRunSSH() != nativeSSH {
		t.Fatal("clearing external SSH host keys must restore native SSH behavior")
	}
}

func TestNetMapNoPeersUsesCurrentCachedState(t *testing.T) {
	b := &LocalBackend{}
	node := &nodeBackend{}
	b.currentNodeAtomic.Store(node)
	if b.NetMapNoPeers() != nil {
		t.Fatal("unexpected network map before the first control update")
	}
	want := &netmap.NetworkMap{SSHPolicy: &tailcfg.SSHPolicy{}}
	node.netMap = want
	if b.NetMapNoPeers() != want || b.NetMapNoPeers().SSHPolicy != want.SSHPolicy {
		t.Fatal("external SSH must observe the current cached network map and policy")
	}
}

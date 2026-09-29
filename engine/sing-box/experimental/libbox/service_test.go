package libbox

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type legacyPlatformFixture struct {
	PlatformInterface
	owner ConnectionOwner
}

func (p *legacyPlatformFixture) UseProcFS() bool { return false }
func (p *legacyPlatformFixture) FindConnectionOwner(int32, string, int32, string, int32) (*ConnectionOwner, error) {
	return &p.owner, nil
}
func (p *legacyPlatformFixture) SystemCertificates() StringIterator {
	return newIterator([]string{"host certificate fixture"})
}
func (p *legacyPlatformFixture) ReadWIFIState() *WIFIState {
	return NewWIFIState("fixture", "fixture")
}

func TestPlatformAdapterPreservesLegacyHostContract(t *testing.T) {
	host := &legacyPlatformFixture{owner: ConnectionOwner{UserId: 10001, AndroidPackageName: "space.pokrov.fixture"}}
	wrapper := WrapPlatformInterface(host).(*platformInterfaceWrapper)
	owner, err := wrapper.FindConnectionOwner(&adapter.FindConnectionOwnerRequest{})
	if err != nil || owner.UserId != host.owner.UserId || len(owner.AndroidPackageNames) != 1 || owner.AndroidPackageNames[0] != host.owner.AndroidPackageName {
		t.Fatal("adapter lost the host-provided Android package")
	}
	certificates := wrapper.SystemCertificates()
	if len(certificates) != 1 || certificates[0] != "host certificate fixture" {
		t.Fatal("adapter lost the existing system certificate callback")
	}
	if wrapper.ReadWIFIState(context.Background()).SSID != "fixture" {
		t.Fatal("adapter lost the existing Wi-Fi callback")
	}
	if wrapper.UsePlatformShell() || wrapper.UsePlatformBridge() || wrapper.UsePlatformNeighborResolver() {
		t.Fatal("adapter advertised host capabilities absent from the existing contract")
	}
	if _, err := wrapper.CreateBridge(adapter.BridgeOptions{}); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("unsupported bridge operation reported success")
	}
}

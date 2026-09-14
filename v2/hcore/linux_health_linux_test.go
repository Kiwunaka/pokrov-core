package hcore

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

type linuxTestOutbound struct {
	adapter.Outbound
	tag, kind string
}

func (o linuxTestOutbound) Tag() string  { return o.tag }
func (o linuxTestOutbound) Type() string { return o.kind }

type linuxTestGroup struct {
	linuxTestOutbound
	selected string
}

func (g linuxTestGroup) Now() string   { return g.selected }
func (g linuxTestGroup) All() []string { return []string{g.selected} }
func (g linuxTestGroup) Tag() string   { return g.linuxTestOutbound.Tag() }
func (g linuxTestGroup) Type() string  { return g.linuxTestOutbound.Type() }

func TestLinuxHealthRejectsDirectLeafAndResolvesCurrentSelection(t *testing.T) {
	proxy := linuxTestOutbound{tag: "proxy", kind: C.TypeVLESS}
	direct := linuxTestOutbound{tag: "direct", kind: C.TypeDirect}
	lookup := func(tag string) (adapter.Outbound, bool) {
		switch tag {
		case "proxy":
			return proxy, true
		case "direct":
			return direct, true
		}
		return nil, false
	}
	group := linuxTestGroup{linuxTestOutbound: linuxTestOutbound{tag: "select", kind: C.TypeSelector}, selected: "direct"}
	if linuxProtectedLeaf(group, lookup) != nil {
		t.Fatal("direct selection accepted as VPN proof")
	}
	group.selected = "proxy"
	if leaf := linuxProtectedLeaf(group, lookup); leaf == nil || leaf.Tag() != "proxy" {
		t.Fatal("selected proxy not captured")
	}
	group.selected = "missing"
	if linuxProtectedLeaf(group, lookup) != nil {
		t.Fatal("missing selection accepted")
	}
}

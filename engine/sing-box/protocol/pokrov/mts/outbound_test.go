package mts

import (
	"github.com/mahsanet/dnstt/noise"
	"github.com/sagernet/sing-box/option"
	"testing"
)

func TestOptionsBoardAndService(t *testing.T) {
	key, e := noise.GeneratePrivkey()
	if e != nil {
		t.Fatal(e)
	}
	o := option.MtsOptions{BoardURL: "https://doski.mts-link.ru/boards/board/33333333-3333-4333-8333-333333333333", PublicKey: noise.EncodeKey(noise.PubkeyFromPrivkey(key)), Service: "api"}
	if _, e = parseOptions(o); e != nil {
		t.Fatal(e)
	}
	o.BoardURL += "?x=1"
	if _, e = parseOptions(o); e == nil {
		t.Fatal("accepted board query")
	}
}

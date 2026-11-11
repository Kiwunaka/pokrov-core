package hcore

import (
	"github.com/mahsanet/dnstt/noise"
	"github.com/sagernet/sing-box/experimental/libbox"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestAPITargetRestricted(t *testing.T) {
	if !allowedAPITarget("app.pokrov.space:443") || !allowedAPITarget("api.pokrov.space:443") {
		t.Fatal("API host rejected")
	}
	if allowedAPITarget("other.example:443") || allowedAPITarget("api.pokrov.space:80") {
		t.Fatal("unapproved target accepted")
	}
}

type apiTestPlatform struct{ libbox.PlatformInterface }

func (apiTestPlatform) LocalDNSTransport() libbox.LocalDNSTransport                       { return nil }
func (apiTestPlatform) UseProcFS() bool                                                   { return false }
func (apiTestPlatform) UsePlatformAutoDetectInterfaceControl() bool                       { return false }
func (apiTestPlatform) StartDefaultInterfaceMonitor(libbox.InterfaceUpdateListener) error { return nil }
func (apiTestPlatform) CloseDefaultInterfaceMonitor(libbox.InterfaceUpdateListener) error { return nil }
func (apiTestPlatform) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	return apiEmptyInterfaces{}, nil
}
func (apiTestPlatform) SystemCertificates() libbox.StringIterator { return nil }
func (apiTestPlatform) UnderNetworkExtension() bool               { return false }
func (apiTestPlatform) IncludeAllNetworks() bool                  { return false }

type apiEmptyInterfaces struct{}

func (apiEmptyInterfaces) Next() *libbox.NetworkInterface { return nil }
func (apiEmptyInterfaces) HasNext() bool                  { return false }
func TestAPIProxyStartsAndStops(t *testing.T) {
	key, e := noise.GeneratePrivkey()
	if e != nil {
		t.Fatal(e)
	}
	port, e := StartApiLoopbackProxy("https://doski.mts-link.ru/boards/board/33333333-3333-4333-8333-333333333333", noise.EncodeKey(noise.PubkeyFromPrivkey(key)), apiTestPlatform{})
	if e != nil {
		t.Fatal(e)
	}
	StopApiLoopbackProxy()
	conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
	if e == nil {
		conn.Close()
		t.Fatal("proxy accepted connection after stop")
	}
}

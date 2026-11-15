package slipstream

import (
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestAdapterDNSUsesSelectedPhysicalInterface(t *testing.T) {
	physicalAddress := windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: [4]byte{192, 0, 2, 53}}
	tunnelAddress := windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: [4]byte{172, 19, 0, 2}}
	physicalDNS := windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{
		Sockaddr:       (*syscall.RawSockaddrAny)(unsafe.Pointer(&physicalAddress)),
		SockaddrLength: int32(unsafe.Sizeof(physicalAddress)),
	}}
	tunnelDNS := windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{
		Sockaddr:       (*syscall.RawSockaddrAny)(unsafe.Pointer(&tunnelAddress)),
		SockaddrLength: int32(unsafe.Sizeof(tunnelAddress)),
	}}
	physical := windows.IpAdapterAddresses{IfIndex: 17, FirstDnsServerAddress: &physicalDNS}
	tunnel := windows.IpAdapterAddresses{IfIndex: 18, FirstDnsServerAddress: &tunnelDNS, Next: &physical}
	if got := adapterDNSServers(&tunnel, 17); !reflect.DeepEqual(got, []string{"192.0.2.53"}) {
		t.Fatalf("physical interface DNS = %v", got)
	}
}

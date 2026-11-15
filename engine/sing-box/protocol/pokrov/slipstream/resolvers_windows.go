package slipstream

import (
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"golang.org/x/sys/windows"
)

func interfaceDNSServers(network *adapter.NetworkInterface) []string {
	if len(network.DNSServers) > 0 {
		return network.DNSServers
	}
	var buffer []byte
	size := uint32(15000)
	for {
		buffer = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_UNICAST,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(buffer)) {
			return nil
		}
	}
	return adapterDNSServers((*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), network.Index)
}

func adapterDNSServers(first *windows.IpAdapterAddresses, interfaceIndex int) []string {
	for item := first; item != nil; item = item.Next {
		if int(item.IfIndex) != interfaceIndex {
			continue
		}
		var servers []string
		for server := item.FirstDnsServerAddress; server != nil; server = server.Next {
			servers = append(servers, server.Address.IP().String())
		}
		return servers
	}
	return nil
}

//go:build !windows

package slipstream

import "github.com/sagernet/sing-box/adapter"

func interfaceDNSServers(network *adapter.NetworkInterface) []string {
	return network.DNSServers
}

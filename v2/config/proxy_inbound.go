package config

import (
	"fmt"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
)

// Loopback is shared by other apps, including apps excluded from the VPN.
func ValidateProxyInbounds(options *option.Options) error {
	for index, inbound := range options.Inbounds {
		var users []auth.User
		switch inbound.Type {
		case C.TypeSOCKS:
			switch settings := inbound.Options.(type) {
			case *option.SocksInboundOptions:
				users = settings.Users
			case option.SocksInboundOptions:
				users = settings.Users
			}
		case C.TypeHTTP, C.TypeMixed:
			switch settings := inbound.Options.(type) {
			case *option.HTTPMixedInboundOptions:
				users = settings.Users
			case option.HTTPMixedInboundOptions:
				users = settings.Users
			}
		default:
			continue
		}
		if len(users) == 0 {
			return fmt.Errorf("proxy inbound %d (%s) requires username and password", index, inbound.Type)
		}
		for _, user := range users {
			if user.Username == "" || user.Password == "" {
				return fmt.Errorf("proxy inbound %d (%s) requires username and password", index, inbound.Type)
			}
		}
	}
	return nil
}

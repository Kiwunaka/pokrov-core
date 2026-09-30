package option

// Native publication authorizes this runtime's admission, never configuration
// alone. The native SOCKS5 service owns its UID, session and egress protection.
type PokrovLocalDPIOutboundOptions struct {
	DialerOptions
	ServerOptions
	VPNOutbound string `json:"vpn_outbound"`
	ServiceID   string `json:"service_id"`
}

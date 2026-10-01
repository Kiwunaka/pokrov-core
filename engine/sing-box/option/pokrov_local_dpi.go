package option

// Native publication authorizes this runtime's admission, never configuration
// alone. The native host owns its child, session and egress protection.
type PokrovLocalDPIOutboundOptions struct {
	DialerOptions
	ServerOptions
	VPNOutbound string `json:"vpn_outbound"`
	ServiceID   string `json:"service_id"`
	// Windows packet filters process the physically bound connection directly.
	// This is not a SOCKS endpoint or permission to admit the runtime.
	WindowsDirect bool `json:"windows_direct,omitempty"`
}

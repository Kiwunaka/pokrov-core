package option

// Populated only from an authenticated device grant by the host compiler.
// The embedded engine enforces the projected limits; it does not issue access.
type PokrovSmartAccessOutboundOptions struct {
	DialerOptions
	LeaseID string `json:"lease_id"`
	IssuedAt string `json:"issued_at"`
	NewFlowsUntil string `json:"new_flows_until"`
	ActiveFlowsUntil string `json:"active_flows_until"`
	RelayAddresses []string `json:"relay_addresses"`
	RelayConnectPolicy *PokrovRelayConnectPolicy `json:"relay_connect_policy,omitempty"`
	Domains []PokrovSmartAccessDomain `json:"domains"`
	MaxNewConnectionsPerMinute int `json:"max_new_connections_per_minute"`
	MaxConcurrentConnections int `json:"max_concurrent_connections"`
}

type PokrovRelayConnectPolicy struct {
	FailureThreshold int `json:"failure_threshold"`
	FailureWindowMS int `json:"failure_window_ms"`
	CooldownMS int `json:"cooldown_ms"`
	ConnectTimeoutMS int `json:"connect_timeout_ms"`
	TotalTimeoutMS int `json:"total_timeout_ms"`
	MaxAttempts int `json:"max_attempts"`
}

type PokrovSmartAccessDomain struct {
	Name string `json:"name"`
	Match string `json:"match"`
}

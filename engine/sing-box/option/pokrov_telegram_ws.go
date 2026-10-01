package option

// The host supplies only the Telegram DC addresses admitted by its service
// policy. Ordinary and explicitly protected application rules retain precedence.
type PokrovTelegramWSOutboundOptions struct {
	DialerOptions
	VPNOutbound string                       `json:"vpn_outbound"`
	Datacenters []PokrovTelegramWSDatacenter `json:"datacenters"`
	ServiceID   string                       `json:"service_id"`
	IssuedAt    string                       `json:"issued_at"`
	ExpiresAt   string                       `json:"expires_at"`
	// One-use proof created by native signed preparation, never catalog or IPC authority.
	NativePreparationID string `json:"native_preparation_id"`
}

type PokrovTelegramWSDatacenter struct {
	ID               int      `json:"id"`
	Addresses        []string `json:"addresses"`
	WebsocketAddress string   `json:"websocket_address"`
}

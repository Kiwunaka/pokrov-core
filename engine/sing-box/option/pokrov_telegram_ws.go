package option

// The host supplies only the Telegram DC addresses admitted by its service
// policy. Ordinary and explicitly protected application rules retain precedence.
type PokrovTelegramWSOutboundOptions struct {
	DialerOptions
	VPNOutbound string                       `json:"vpn_outbound"`
	Datacenters []PokrovTelegramWSDatacenter `json:"datacenters"`
}

type PokrovTelegramWSDatacenter struct {
	ID               int      `json:"id"`
	Addresses        []string `json:"addresses"`
	WebsocketAddress string   `json:"websocket_address"`
}

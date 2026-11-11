package option

type MtsOptions struct {
	DialerOptions
	BoardURL  string      `json:"board_url"`
	PublicKey string      `json:"public_key"`
	Service   string      `json:"service,omitempty"`
	Network   NetworkList `json:"network,omitempty"`
}

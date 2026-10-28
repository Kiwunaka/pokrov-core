package option

type SlipstreamOptions struct {
	DialerOptions
	Domain      string      `json:"domain"`
	Resolvers   []string    `json:"resolvers"`
	Certificate string      `json:"certificate"`
	Network     NetworkList `json:"network,omitempty"`
}

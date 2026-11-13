package option

type VkOptions struct {
	DialerOptions
	ServerOptions
	CallURL string `json:"call_url"`
}

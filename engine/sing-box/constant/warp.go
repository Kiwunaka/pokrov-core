package constant

type WARPConfig struct {
	PrivateKey string `json:"private_key"`
	ClientID   string `json:"client_id,omitempty"`
	Interface  struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
	Peers []struct {
		PublicKey string `json:"public_key"`
		Endpoint  struct {
			V4    string `json:"v4"`
			V6    string `json:"v6"`
			Host  string `json:"host"`
			Ports []int  `json:"ports"`
		} `json:"endpoint"`
	} `json:"peers"`
}

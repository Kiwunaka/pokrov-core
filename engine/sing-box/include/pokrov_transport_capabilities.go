package include

import (
	"encoding/json"
	"sort"
)

// TransportCapabilities reports compiled client features, never reachability,
// profile validity, signed policy references or host/TUN readiness. Registry
// presence is insufficient: disabled protocols also register error stubs.
func TransportCapabilities() string {
	features := []string{"pokrov_ats_lease_v1", "singbox_grpc_v1", "singbox_tls_v1", "singbox_vless_v1", "singbox_xhttp_v1"}
	if pokrovTransportUTLS {
		features = append(features, "singbox_utls_v1", "singbox_reality_v1")
	}
	if pokrovTransportQUIC {
		features = append(features, "singbox_hysteria2_v1")
	}
	if pokrovTransportAWG {
		features = append(features, "pokrov_awg31_endpoint_v1")
	}
	sort.Strings(features)
	// Only fixed ASCII strings and an integer enter this bounded descriptor.
	encoded, _ := json.Marshal(struct {
		Schema int `json:"schema"`
		Features []string `json:"features"`
	}{1, features})
	return string(encoded)
}

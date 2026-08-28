package ray2sing

import (
	"errors"

	T "github.com/sagernet/sing-box/option"
)

var errLegacyHY2ConverterDisabled = errors.New("raw Hysteria2 URI conversion is disabled; use pokrov.hy2.outbound.v1")

// Hysteria2Singbox deliberately rejects subscription-style URI material. The
// runtime engine still includes the official sing-box Hysteria2 outbound, but
// POKROV only accepts it through the bounded, provenance-bound managed profile.
func Hysteria2Singbox(string) (*T.Outbound, error) {
	return nil, errLegacyHY2ConverterDisabled
}

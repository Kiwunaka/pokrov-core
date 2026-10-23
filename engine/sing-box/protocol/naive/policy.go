package naive

import "github.com/sagernet/sing-box/option"

// ProtectedH2 limits managed fallback admission to the authenticated TCP-only
// Naive leaf. General imported Naive profiles keep their existing capabilities.
func ProtectedH2(options *option.NaiveOutboundOptions) bool {
	if options == nil || options.Server == "" || options.ServerPort == 0 ||
		options.Username == "" || options.Password == "" || options.Detour != "" || options.QUIC ||
		(options.UDPOverTCP != nil && options.UDPOverTCP.Enabled) {
		return false
	}
	tls := options.TLS
	return tls != nil && tls.Enabled && tls.ServerName != "" && !tls.Insecure && !tls.DisableSNI &&
		len(tls.ALPN) == 0 && !tls.Fragment && (tls.RecordFragment == nil || !*tls.RecordFragment) &&
		(tls.UTLS == nil || !tls.UTLS.Enabled) && (tls.Reality == nil || !tls.Reality.Enabled) &&
		(tls.ECH == nil || !tls.ECH.Enabled)
}

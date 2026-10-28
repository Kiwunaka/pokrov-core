package slipstream

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

type tunnelConfig struct {
	domain      string
	resolver    netip.AddrPort
	certificate []byte
}

func parseOptions(options option.SlipstreamOptions) (*tunnelConfig, error) {
	if len(options.Resolvers) != 1 || options.Detour != "" {
		return nil, errors.New("slipstream requires one UDP resolver without a detour")
	}
	resolver, err := netip.ParseAddrPort(options.Resolvers[0])
	if err != nil || resolver.Port() == 0 || resolver.Addr().IsUnspecified() || resolver.Addr().IsMulticast() {
		return nil, errors.New("slipstream requires a numeric UDP resolver address and port")
	}
	for _, network := range options.Network.Build() {
		if network != N.NetworkTCP && options.Network != "" {
			return nil, errors.New("slipstream transport supports TCP streams only")
		}
	}
	domain := strings.TrimSuffix(strings.ToLower(options.Domain), ".")
	if len(domain) == 0 || len(domain) >= 240 {
		return nil, errors.New("invalid slipstream domain")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, errors.New("invalid slipstream domain")
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return nil, errors.New("invalid slipstream domain")
			}
		}
	}
	block, rest := pem.Decode([]byte(options.Certificate))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("slipstream requires one pinned server leaf certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, errors.New("invalid slipstream server certificate")
	}
	return &tunnelConfig{domain, resolver, pem.EncodeToMemory(block)}, nil
}

// ProtectedVLESSDetour recognizes the personal TCP-only backend carried by a
// certificate-pinned Slipstream tunnel. The carrier has no destination framing.
func ProtectedVLESSDetour(vless *option.VLESSOutboundOptions, tunnel *option.SlipstreamOptions) bool {
	if vless == nil || tunnel == nil || vless.Detour == "" || vless.UUID == "" ||
		vless.Server != "127.0.0.1" || vless.ServerPort != 12543 || vless.Flow != "" ||
		vless.Network != N.NetworkTCP || tunnel.Network != N.NetworkTCP ||
		vless.TLS != nil || vless.Transport != nil || vless.Multiplex != nil && vless.Multiplex.Enabled {
		return false
	}
	_, err := parseOptions(*tunnel)
	return err == nil
}

package awg

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
)

const contractID = "pokrov.awg2.endpoint.v1"

var allowedMTU = map[uint32]struct{}{
	1280: {},
	1400: {},
	1408: {},
}

func validateEndpointOptions(options option.AwgEndpointOptions) error {
	if options.UseIntegratedTun {
		return fmt.Errorf("%s: integrated system TUN is forbidden", contractID)
	}
	if _, loaded := allowedMTU[options.MTU]; !loaded {
		return fmt.Errorf("%s: unsupported MTU", contractID)
	}
	if err := validateKey("private_key", options.PrivateKey, true); err != nil {
		return err
	}
	if len(options.Address) < 1 || len(options.Address) > 2 {
		return fmt.Errorf("%s: address prefix count must be between one and two", contractID)
	}
	for _, prefix := range options.Address {
		if !prefix.IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return fmt.Errorf("%s: invalid client address prefix", contractID)
		}
	}
	if options.Jc <= 0 || options.Jmin <= 0 || options.Jmax <= 0 || options.Jmin > options.Jmax {
		return fmt.Errorf("%s: invalid junk packet bounds", contractID)
	}
	if options.S1 < 0 || options.S2 < 0 || options.S3 < 0 || options.S4 < 0 {
		return fmt.Errorf("%s: padding values must be non-negative", contractID)
	}
	for index, header := range []string{options.H1, options.H2, options.H3, options.H4} {
		if err := validateHeaderRange(header); err != nil {
			return fmt.Errorf("%s: invalid h%d range", contractID, index+1)
		}
	}
	if options.I1 != "" || options.I2 != "" || options.I3 != "" || options.I4 != "" || options.I5 != "" {
		return fmt.Errorf("%s: instruction chains are outside the v1 subset", contractID)
	}
	if len(options.Peers) != 1 {
		return fmt.Errorf("%s: exactly one peer is required", contractID)
	}
	peer := options.Peers[0]
	peerAddress, err := netip.ParseAddr(peer.Address)
	if err != nil || peerAddress.IsUnspecified() || peerAddress.IsMulticast() {
		return fmt.Errorf("%s: peer address must be an IP literal", contractID)
	}
	if peer.Port == 0 {
		return fmt.Errorf("%s: peer port is required", contractID)
	}
	if err := validateKey("public_key", peer.PublicKey, true); err != nil {
		return err
	}
	if err := validateKey("preshared_key", peer.PresharedKey, false); err != nil {
		return err
	}
	if len(peer.AllowedIPs) < 1 || len(peer.AllowedIPs) > 2 {
		return fmt.Errorf("%s: allowed IP prefix count must be between one and two", contractID)
	}
	for _, prefix := range peer.AllowedIPs {
		if !prefix.IsValid() {
			return fmt.Errorf("%s: invalid allowed IP prefix", contractID)
		}
	}
	if peer.PersistentKeepaliveInterval > 600 {
		return fmt.Errorf("%s: persistent keepalive exceeds the supported bound", contractID)
	}
	return nil
}

func validateKey(name string, encoded string, required bool) error {
	if encoded == "" && !required {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s: %s must be a 32-byte base64 key", contractID, name)
	}
	return nil
}

func validateHeaderRange(value string) error {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		return fmt.Errorf("invalid header range")
	}
	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid header range")
	}
	end := start
	if len(parts) == 2 {
		end, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid header range")
		}
	}
	if end < start {
		return fmt.Errorf("invalid header range")
	}
	return nil
}

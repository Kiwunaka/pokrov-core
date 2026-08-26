package awg

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
)

const (
	awg2ContractID  = "pokrov.awg2.endpoint.v1"
	awg31ContractID = "pokrov.awg31.endpoint.v1"
	contractID      = awg2ContractID
)

var allowedMTU = map[uint32]struct{}{
	1280: {},
	1400: {},
	1408: {},
}

const (
	maximumJunkPacketCount = 128
	maximumAWG2JunkSize    = 65535
	maximumAWG31JunkSize   = 1279
	maximumPaddingSize     = 65535
)

func validateEndpointOptions(options option.AwgEndpointOptions) error {
	selectedContractID := options.ContractID
	if selectedContractID == "" {
		selectedContractID = awg2ContractID
	}
	if selectedContractID != awg2ContractID && selectedContractID != awg31ContractID {
		return fmt.Errorf("pokrov.awg.endpoint: unsupported contract_id")
	}
	if options.UseIntegratedTun {
		return fmt.Errorf("%s: integrated system TUN is forbidden", selectedContractID)
	}
	if _, loaded := allowedMTU[options.MTU]; !loaded {
		return fmt.Errorf("%s: unsupported MTU", selectedContractID)
	}
	if err := validateKey(selectedContractID, "private_key", options.PrivateKey, true); err != nil {
		return err
	}
	if len(options.Address) < 1 || len(options.Address) > 2 {
		return fmt.Errorf("%s: address prefix count must be between one and two", selectedContractID)
	}
	for _, prefix := range options.Address {
		if !prefix.IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return fmt.Errorf("%s: invalid client address prefix", selectedContractID)
		}
	}
	maximumJunkSize := maximumAWG2JunkSize
	if selectedContractID == awg31ContractID {
		maximumJunkSize = maximumAWG31JunkSize
	}
	if options.Jc <= 0 || options.Jc > maximumJunkPacketCount ||
		options.Jmin <= 0 || options.Jmin > maximumJunkSize ||
		options.Jmax <= 0 || options.Jmax > maximumJunkSize ||
		options.Jmin > options.Jmax {
		return fmt.Errorf("%s: invalid junk packet bounds", selectedContractID)
	}
	if options.S1 < 0 || options.S1 > maximumPaddingSize ||
		options.S2 < 0 || options.S2 > maximumPaddingSize ||
		options.S3 < 0 || options.S3 > maximumPaddingSize ||
		options.S4 < 0 || options.S4 > maximumPaddingSize {
		return fmt.Errorf("%s: padding values are outside the supported range", selectedContractID)
	}
	for index, header := range []string{options.H1, options.H2, options.H3, options.H4} {
		if err := validateHeaderRange(header); err != nil {
			return fmt.Errorf("%s: invalid h%d range", selectedContractID, index+1)
		}
	}
	if len(options.Peers) != 1 {
		return fmt.Errorf("%s: exactly one peer is required", selectedContractID)
	}
	peer := options.Peers[0]
	peerAddress, err := netip.ParseAddr(peer.Address)
	if err != nil || peerAddress.IsUnspecified() || peerAddress.IsMulticast() {
		return fmt.Errorf("%s: peer address must be an IP literal", selectedContractID)
	}
	if peer.Port == 0 {
		return fmt.Errorf("%s: peer port is required", selectedContractID)
	}
	if err := validateKey(selectedContractID, "public_key", peer.PublicKey, true); err != nil {
		return err
	}
	if err := validateKey(selectedContractID, "preshared_key", peer.PresharedKey, false); err != nil {
		return err
	}
	if len(peer.AllowedIPs) < 1 || len(peer.AllowedIPs) > 2 {
		return fmt.Errorf("%s: allowed IP prefix count must be between one and two", selectedContractID)
	}
	for _, prefix := range peer.AllowedIPs {
		if !prefix.IsValid() {
			return fmt.Errorf("%s: invalid allowed IP prefix", selectedContractID)
		}
	}
	if peer.PersistentKeepaliveInterval > 600 {
		return fmt.Errorf("%s: persistent keepalive exceeds the supported bound", selectedContractID)
	}

	if selectedContractID == awg2ContractID {
		return validateAWG2Subset(options)
	}
	return validateAWG31Subset(options)
}

func validateAWG2Subset(options option.AwgEndpointOptions) error {
	if options.I1 != "" || options.I2 != "" || options.I3 != "" || options.I4 != "" || options.I5 != "" {
		return fmt.Errorf("%s: instruction chains are outside the v1 subset", awg2ContractID)
	}
	if options.HeaderProtectionKey != "" || options.ContentPaddingAddition != "" ||
		options.RekeyAfterTime != "" || options.RekeyTimeout != "" || options.RejectAfterTime != "" ||
		options.KeepaliveTimeout != "" || options.MaxHandshakeAttempts != "" || options.RandomTrailers ||
		options.Peers[0].PersistentKeepaliveIntervalRange != "" {
		return fmt.Errorf("%s: AWG 3.1 fields are outside the v1 subset", awg2ContractID)
	}
	return nil
}

func validateAWG31Subset(options option.AwgEndpointOptions) error {
	if options.S1 < 12 || options.S2 < 12 || options.S3 < 12 || options.S4 < 12 {
		return fmt.Errorf("%s: header protection requires s1-s4 >= 12", awg31ContractID)
	}
	if err := validateKey(awg31ContractID, "header_protection_key", options.HeaderProtectionKey, true); err != nil {
		return err
	}
	for index, instruction := range []string{options.I1, options.I2, options.I3, options.I4, options.I5} {
		if instruction == "" {
			continue
		}
		if err := validateInstructionChain(instruction); err != nil {
			return fmt.Errorf("%s: invalid i%d instruction chain: %w", awg31ContractID, index+1, err)
		}
	}
	for _, field := range []struct {
		name    string
		value   string
		minimum uint64
		maximum uint64
	}{
		{"content_padding_addition", options.ContentPaddingAddition, 0, 512},
		{"rekey_after_time", options.RekeyAfterTime, 30, 3600},
		{"rekey_timeout", options.RekeyTimeout, 1, 60},
		{"reject_after_time", options.RejectAfterTime, 30, 7200},
		{"keepalive_timeout", options.KeepaliveTimeout, 1, 600},
		{"max_handshake_attempts", options.MaxHandshakeAttempts, 1, 100},
	} {
		if field.value == "" {
			continue
		}
		if err := validateUintRange(field.value, field.minimum, field.maximum); err != nil {
			return fmt.Errorf("%s: invalid %s range", awg31ContractID, field.name)
		}
	}
	peer := options.Peers[0]
	if peer.PersistentKeepaliveInterval != 0 && peer.PersistentKeepaliveIntervalRange != "" {
		return fmt.Errorf("%s: persistent keepalive scalar and range are mutually exclusive", awg31ContractID)
	}
	if peer.PersistentKeepaliveIntervalRange != "" {
		if err := validateUintRange(peer.PersistentKeepaliveIntervalRange, 1, 600); err != nil {
			return fmt.Errorf("%s: invalid persistent keepalive range", awg31ContractID)
		}
	}
	return nil
}

func validateKey(selectedContractID string, name string, encoded string, required bool) error {
	if encoded == "" && !required {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s: %s must be a 32-byte base64 key", selectedContractID, name)
	}
	return nil
}

var instructionTokenPattern = regexp.MustCompile(`(?:<t>|<b 0x[0-9A-Fa-f]+>|<(?:r|rd|rc) [1-9][0-9]{0,3}>)`)

func validateInstructionChain(value string) error {
	if len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("unsafe instruction encoding")
	}
	matches := instructionTokenPattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return fmt.Errorf("no supported instruction tags")
	}
	offset := 0
	generatedBytes := 0
	for _, match := range matches {
		if match[0] != offset {
			return fmt.Errorf("unsupported instruction text")
		}
		token := value[match[0]:match[1]]
		switch {
		case token == "<t>":
			generatedBytes += 4
		case strings.HasPrefix(token, "<b 0x"):
			hexLength := len(token) - len("<b 0x") - 1
			if hexLength == 0 || hexLength%2 != 0 {
				return fmt.Errorf("static byte tag must contain complete bytes")
			}
			generatedBytes += hexLength / 2
		default:
			parts := strings.Fields(strings.Trim(token, "<>"))
			if len(parts) != 2 {
				return fmt.Errorf("random tag must contain one size")
			}
			size, err := strconv.Atoi(parts[1])
			if err != nil || size < 1 || size > 512 {
				return fmt.Errorf("random tag size is outside the supported bound")
			}
			generatedBytes += size
		}
		offset = match[1]
	}
	if offset != len(value) || generatedBytes < 1 || generatedBytes > 512 {
		return fmt.Errorf("instruction packet must be between 1 and 512 bytes")
	}
	return nil
}

func validateUintRange(value string, minimum uint64, maximum uint64) error {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		return fmt.Errorf("invalid range")
	}
	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid range")
	}
	end := start
	if len(parts) == 2 {
		end, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid range")
		}
	}
	if start < minimum || end < start || end > maximum {
		return fmt.Errorf("range outside supported bounds")
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

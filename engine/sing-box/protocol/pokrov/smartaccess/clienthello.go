package smartaccess

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

var errInvalidClientHello = errors.New("invalid TLS ClientHello")

// Parser adapted from the platform owned-smart-dns ClientHello boundary.
// Reads and replays the exact TLS records; never terminates or rewrites TLS.
func readClientHello(connection net.Conn) ([]byte, string, error) {
	const maximum = 65535
	var raw []byte
	var handshake []byte
	expectedHandshake := -1
	for len(raw) < maximum {
		header := make([]byte, 5)
		if _, err := io.ReadFull(connection, header); err != nil {
			return nil, "", fmt.Errorf("%w: record header", errInvalidClientHello)
		}
		if header[0] != 22 || header[1] != 3 {
			return nil, "", fmt.Errorf("%w: record type", errInvalidClientHello)
		}
		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength == 0 || len(raw)+5+recordLength > maximum {
			return nil, "", fmt.Errorf("%w: record length", errInvalidClientHello)
		}
		body := make([]byte, recordLength)
		if _, err := io.ReadFull(connection, body); err != nil {
			return nil, "", fmt.Errorf("%w: record body", errInvalidClientHello)
		}
		raw = append(raw, header...)
		raw = append(raw, body...)
		handshake = append(handshake, body...)
		if len(handshake) >= 4 && expectedHandshake < 0 {
			if handshake[0] != 1 {
				return nil, "", fmt.Errorf("%w: handshake type", errInvalidClientHello)
			}
			expectedHandshake = 4 + (int(handshake[1]) << 16) + (int(handshake[2]) << 8) + int(handshake[3])
			if expectedHandshake > maximum || expectedHandshake < 42 {
				return nil, "", fmt.Errorf("%w: handshake length", errInvalidClientHello)
			}
		}
		if expectedHandshake >= 0 && len(handshake) >= expectedHandshake {
			name, err := parseClientHelloSNI(handshake[:expectedHandshake])
			if err != nil {
				return nil, "", err
			}
			return raw, name, nil
		}
	}
	return nil, "", fmt.Errorf("%w: size limit", errInvalidClientHello)
}

func parseClientHelloSNI(handshake []byte) (string, error) {
	if len(handshake) < 4 || handshake[0] != 1 ||
		len(handshake) != 4+(int(handshake[1])<<16)+(int(handshake[2])<<8)+int(handshake[3]) {
		return "", errInvalidClientHello
	}
	body := handshake[4:]
	if len(body) < 34 {
		return "", errInvalidClientHello
	}
	offset := 34
	if offset >= len(body) {
		return "", errInvalidClientHello
	}
	sessionLength := int(body[offset])
	offset += 1 + sessionLength
	if offset+2 > len(body) {
		return "", errInvalidClientHello
	}
	cipherLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2 + cipherLength
	if cipherLength < 2 || cipherLength%2 != 0 || offset >= len(body) {
		return "", errInvalidClientHello
	}
	compressionLength := int(body[offset])
	offset += 1 + compressionLength
	if compressionLength < 1 || offset+2 > len(body) {
		return "", errInvalidClientHello
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extensionsLength != len(body) {
		return "", errInvalidClientHello
	}
	extensionsEnd := offset + extensionsLength
	var serverName string
	for offset < extensionsEnd {
		if offset+4 > extensionsEnd {
			return "", errInvalidClientHello
		}
		extensionType := binary.BigEndian.Uint16(body[offset : offset+2])
		extensionLength := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if offset+extensionLength > extensionsEnd {
			return "", errInvalidClientHello
		}
		// ECH hides the destination in ClientHelloInner; an allowed outer SNI
		// cannot authorize this selective relay (including ECH GREASE).
		if extensionType == 0xfe0d {
			return "", errInvalidClientHello
		}
		if extensionType == 0 {
			if serverName != "" || extensionLength < 5 {
				return "", errInvalidClientHello
			}
			extension := body[offset : offset+extensionLength]
			listLength := int(binary.BigEndian.Uint16(extension[:2]))
			if listLength != len(extension)-2 {
				return "", errInvalidClientHello
			}
			nameOffset := 2
			for nameOffset < len(extension) {
				if nameOffset+3 > len(extension) {
					return "", errInvalidClientHello
				}
				nameType := extension[nameOffset]
				nameLength := int(binary.BigEndian.Uint16(extension[nameOffset+1 : nameOffset+3]))
				nameOffset += 3
				if nameLength == 0 || nameOffset+nameLength > len(extension) {
					return "", errInvalidClientHello
				}
				if nameType == 0 {
					if serverName != "" {
						return "", errInvalidClientHello
					}
					normalized, err := normalizeDomain(string(extension[nameOffset : nameOffset+nameLength]))
					if err != nil {
						return "", errInvalidClientHello
					}
					serverName = normalized
				}
				nameOffset += nameLength
			}
		}
		offset += extensionLength
	}
	if serverName == "" {
		return "", errInvalidClientHello
	}
	return serverName, nil
}

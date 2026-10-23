package transport

import (
	"errors"
	"io"
	"net/http"
)

// RFC 8484 section 6 bounds an application/dns-message body to 65535 bytes.
const maxDNSMessageSize = 65535

var errDNSMessageTooLarge = errors.New("DNS message exceeds 65535 bytes")

func readDNSMessageBody(response *http.Response) ([]byte, error) {
	// Do not allocate from an untrusted Content-Length, including on 32-bit
	// clients. Unknown/chunked lengths must obey the same wire limit.
	if response.ContentLength > maxDNSMessageSize {
		return nil, errDNSMessageTooLarge
	}
	message, err := io.ReadAll(io.LimitReader(response.Body, maxDNSMessageSize+1))
	if err != nil {
		return nil, err
	}
	if len(message) > maxDNSMessageSize {
		return nil, errDNSMessageTooLarge
	}
	if response.ContentLength > 0 && int64(len(message)) < response.ContentLength {
		return nil, io.ErrUnexpectedEOF
	}
	return message, nil
}

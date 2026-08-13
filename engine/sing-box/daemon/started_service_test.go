package daemon

import (
	"context"
	"errors"
	"testing"
)

func TestURLTestErrorCategory(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{name: "none", expected: "none"},
		{name: "deadline", err: context.DeadlineExceeded, expected: "deadline_exceeded"},
		{name: "cancelled", err: context.Canceled, expected: "context_canceled"},
		{name: "dns", err: errors.New("lookup example.test: no such host"), expected: "dns_lookup"},
		{name: "certificate", err: errors.New("x509: certificate has expired"), expected: "tls_certificate"},
		{name: "reality", err: errors.New("reality handshake failed"), expected: "reality_handshake"},
		{name: "http", err: errors.New("returned status 403"), expected: "http_rejected"},
		{name: "timeout", err: errors.New("read: i/o timeout"), expected: "io_timeout"},
		{name: "other", err: errors.New("broken transport"), expected: "transport_failure"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := urlTestErrorCategory(test.err); actual != test.expected {
				t.Fatalf("unexpected category: got %q, want %q", actual, test.expected)
			}
		})
	}
}

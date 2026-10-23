package transport

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/http"
	"testing"
)

type countedDNSBody struct {
	remaining int
	read      int
	failure   error
}

func (b *countedDNSBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		if b.failure != nil {
			return 0, b.failure
		}
		return 0, io.EOF
	}
	n := min(len(p), b.remaining)
	for i := range p[:n] {
		p[i] = 0xa5
	}
	b.remaining -= n
	b.read += n
	return n, nil
}

func (*countedDNSBody) Close() error { return nil }

func TestReadDNSMessageBodyBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length int64
		size   int
		want   error
		read   int
	}{
		{"known_limit", 65535, 65535, nil, 65535},
		{"unknown_limit", -1, 65535, nil, 65535},
		{"zero_length_limit", 0, 65535, nil, 65535},
		{"known_oversize", 65536, 65536, errDNSMessageTooLarge, 0},
		{"huge_declared_length", math.MaxInt64, 0, errDNSMessageTooLarge, 0},
		{"unknown_oversize", -1, 1 << 20, errDNSMessageTooLarge, 65536},
		{"zero_length_oversize", 0, 1 << 20, errDNSMessageTooLarge, 65536},
		{"misreported_oversize", 12, 1 << 20, errDNSMessageTooLarge, 65536},
		{"truncated", 12, 11, io.ErrUnexpectedEOF, 11},
		{"empty_unknown", -1, 0, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &countedDNSBody{remaining: tc.size}
			got, err := readDNSMessageBody(&http.Response{ContentLength: tc.length, Body: body})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if body.read != tc.read {
				t.Fatalf("read %d bytes, want %d", body.read, tc.read)
			}
			if err != nil && got != nil {
				t.Fatal("failed response returned partial payload")
			}
			if err == nil && len(got) != tc.size {
				t.Fatalf("payload size = %d, want %d", len(got), tc.size)
			}
		})
	}
}

func TestReadDNSMessageBodyReadFailure(t *testing.T) {
	failure := errors.New("synthetic read failure")
	body := &countedDNSBody{remaining: 13, failure: failure}
	got, err := readDNSMessageBody(&http.Response{ContentLength: -1, Body: body})
	if !errors.Is(err, failure) || got != nil {
		t.Fatalf("got %d bytes, %v; partial response must be discarded", len(got), err)
	}
}

func TestReadDNSMessageBodyPreservesWireBytes(t *testing.T) {
	// A complete DNS response: one question and one compressed A answer.
	wire := []byte{
		0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		1, 'a', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1,
		0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1,
	}
	for _, length := range []int64{-1, int64(len(wire))} {
		got, err := readDNSMessageBody(&http.Response{
			ContentLength: length, Body: io.NopCloser(bytes.NewReader(wire)),
		})
		if err != nil || !bytes.Equal(got, wire) {
			t.Fatalf("wire payload changed: %v", err)
		}
	}
}

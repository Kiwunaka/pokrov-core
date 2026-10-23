package tsdial

import (
    "context"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestDoHResponseBound(t *testing.T) {
    for _, tc := range []struct {
        name string
        size int
        wantError bool
    }{
        {"within_limit", 65535, false},
        {"over_limit", 65536, true},
    } {
        t.Run(tc.name, func(t *testing.T) {
            server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/dns-message")
                _, _ = io.WriteString(w, strings.Repeat("x", tc.size))
            }))
            defer server.Close()
            conn := &dohConn{ctx: context.Background(), baseURL: server.URL}
            n, err := conn.Write([]byte{1, 2, 3})
            if (err != nil) != tc.wantError {
                t.Fatalf("Write() = %d, %v; wantError=%v", n, err, tc.wantError)
            }
            if tc.wantError && conn.rbuf.Len() != 0 {
                t.Fatalf("oversized response retained %d bytes", conn.rbuf.Len())
            }
            if !tc.wantError && conn.rbuf.Len() != tc.size {
                t.Fatalf("got %d bytes, want %d", conn.rbuf.Len(), tc.size)
            }
        })
    }
}

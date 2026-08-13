package cloudflare

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestCreateProfileUsesCompatibleRequestHeaders(t *testing.T) {
	api := &CloudflareApi{client: http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", request.Method)
		}
		if request.URL.String() != baseUrl+"reg" {
			t.Fatalf("unexpected URL: %s", request.URL)
		}
		if got := request.Header.Get("User-Agent"); got != cloudflareAPIUserAgent {
			t.Fatalf("unexpected User-Agent: %q", got)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected Content-Type: %q", got)
		}
		if got := request.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("unexpected Accept: %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"result":{"id":"test-profile"}}`)),
		}, nil
	})}}

	profile, err := api.CreateProfile(context.Background(), "test-public-key")
	if err != nil {
		t.Fatal(err)
	}
	if profile.ID != "test-profile" {
		t.Fatalf("unexpected profile ID: %q", profile.ID)
	}
}

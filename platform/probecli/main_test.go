package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsInvalidRequestWithoutEcho(t *testing.T) {
	result := run([]string{"key-s3cr3t"})
	if result.Success || result.FailureKind != "invalid_request" {
		t.Fatalf("unexpected result: %s", result.JSON())
	}
	if strings.Contains(result.JSON(), "key-s3cr3t") {
		t.Fatal("request material leaked into result")
	}
}

func TestRunRejectsInvalidProfileWithoutEcho(t *testing.T) {
	path := filepath.Join(t.TempDir(), "address-private.example.json")
	if err := os.WriteFile(path, []byte(`{"outbounds":[{"type":"vless","password":"key-s3cr3t"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result := run([]string{path, "uplink-private"})
	if result.Success || result.FailureKind != "invalid_profile" {
		t.Fatalf("unexpected result: %s", result.JSON())
	}
	for _, secret := range []string{"address-private", "key-s3cr3t", "uplink-private"} {
		if strings.Contains(result.JSON(), secret) {
			t.Fatal("profile or request material leaked into result")
		}
	}
}

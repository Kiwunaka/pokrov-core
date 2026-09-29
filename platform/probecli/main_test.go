package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFixedProbeTimeout(t *testing.T) {
	if probeTimeout != 12*time.Second {
		t.Fatal("fixed probe must allow the 204 and 64 KiB checks within a 12-second budget")
	}
}

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
	// Windows does not preserve Unix file modes in this test. Both stages are safe.
	if result.Stage != "parse_profile" && result.Stage != "profile_file" {
		t.Fatalf("unexpected safe failure stage: %q", result.Stage)
	}
	if !strings.Contains(result.JSON(), `"stage":"`+result.Stage+`"`) {
		t.Fatal("failure stage missing from JSON output")
	}
	for _, secret := range []string{"address-private", "key-s3cr3t", "uplink-private"} {
		if strings.Contains(result.JSON(), secret) {
			t.Fatal("profile or request material leaked into result")
		}
	}
}

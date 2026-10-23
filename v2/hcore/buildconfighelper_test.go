//go:build !windows

package hcore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	hcommon "github.com/Kiwunaka/POKROV-core/v2/hcommon"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestParseKeepsStoredCredentialsOwnerOnly(t *testing.T) {
	const credential = "00000000-0000-4000-8000-000000000001"
	const profile = `{"type":"vless","tag":"test","server":"192.0.2.1","server_port":443,"uuid":"` + credential + `"}`
	for _, existing := range []bool{false, true} {
		name := "new"
		if existing {
			name = "existing-readable"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile.json")
			if existing {
				if err := os.WriteFile(path, []byte("old profile"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			response, err := Parse(libbox.BaseContext(nil), &ParseRequest{Content: profile, ConfigPath: path})
			if err != nil || response == nil || response.ResponseCode != hcommon.ResponseCode_OK {
				t.Fatalf("synthetic profile parse failed: %v", err)
			}
			stored, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(stored) != response.Content || !strings.Contains(string(stored), credential) {
				t.Fatal("parsed profile was not persisted intact")
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("credential-bearing profile mode = %o, want 600", info.Mode().Perm())
			}
		})
	}
}

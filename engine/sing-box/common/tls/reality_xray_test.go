//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

// Optional owned local fixture: each version directory contains its unmodified
// Xray executable. The decoy and all proxy/control sockets stay on loopback.
func TestRealityXrayCompatibility(t *testing.T) {
	directory := os.Getenv("POKROV_XRAY_TEST_DIRECTORY")
	if directory == "" {
		t.Skip("set POKROV_XRAY_TEST_DIRECTORY to the local Xray version directories")
	}
	decoy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer decoy.Close()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v26.6.27", "v26.7.28", "v26.9.9"} {
		t.Run(version, func(t *testing.T) {
			executable := "xray"
			if runtime.GOOS == "windows" {
				executable += ".exe"
			}
			reservation, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := reservation.Addr().(*net.TCPAddr)
			reservation.Close()
			config := map[string]any{
				"log": map[string]any{"loglevel": "none"},
				"inbounds": []any{map[string]any{
					"listen": "127.0.0.1", "port": address.Port, "protocol": "vless",
					"settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": "00000000-0000-4000-8000-000000000001"}}},
					"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{
						"dest": decoy.Listener.Addr().String(), "serverNames": []string{"example.com"},
						"privateKey": base64.RawURLEncoding.EncodeToString(private.Bytes()), "shortIds": []string{"0123456789abcdef"},
						"minClientVer": "26.3.27",
					}},
				}},
				"outbounds": []any{map[string]any{"protocol": "freedom"}},
			}
			encoded, _ := json.Marshal(config)
			path := filepath.Join(t.TempDir(), "xray.json")
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, filepath.Join(directory, version, executable), "run", "-config", path)
			if err := command.Start(); err != nil {
				t.Fatal("local Xray fixture could not start:", err)
			}
			defer func() { command.Process.Kill(); command.Wait() }()
			var conn net.Conn
			for ctx.Err() == nil {
				conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address.String())
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				t.Fatal("local Xray fixture did not listen:", err)
			}
			defer conn.Close()
			client, err := NewRealityClient(ctx, logger.NOP(), "example.com", option.OutboundTLSOptions{
				Enabled: true, ServerName: "example.com",
				UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
				Reality: &option.OutboundRealityOptions{Enabled: true,
					PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), ShortID: "0123456789abcdef"},
			})
			if err != nil {
				t.Fatal(err)
			}
			secured, err := ClientHandshake(ctx, conn, client)
			if err != nil {
				t.Fatal("REALITY verification failed against local "+version+":", err)
			}
			secured.Close()
		})
	}
}

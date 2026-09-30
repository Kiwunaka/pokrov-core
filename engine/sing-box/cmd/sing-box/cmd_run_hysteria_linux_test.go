//go:build linux && with_quic && pokrov_lab

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestHysteriaSIGUSR2WritesLoadedProofWithoutRestart(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	tlsServer := httptest.NewTLSServer(http.NewServeMux())
	certificate := tlsServer.TLS.Certificates[0]
	tlsServer.Close()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"log":          map[string]bool{"disabled": true},
		"experimental": map[string]bool{"hysteria_reload": true},
		"inbounds": []any{map[string]any{
			"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": 0, "ignore_client_bandwidth": true,
			"users": []any{map[string]string{"name": "a", "password": "synthetic-a"}, map[string]string{"name": "b", "password": "synthetic-b"}},
			"tls": map[string]any{"enabled": true,
				"certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))},
				"key":         []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}},
		}},
		"outbounds": []any{map[string]string{"type": "direct", "tag": "account"}},
		"route":     map[string]any{"rules": []any{map[string]string{"action": "route", "outbound": "account"}}},
	}
	write := func() string {
		data, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		return hex.EncodeToString(digest[:])
	}
	initialDigest := write()
	oldCtx, oldPaths, oldDirectories, oldWorking, oldColor := globalCtx, configPaths, configDirectories, workingDir, disableColor
	configPaths, configDirectories, workingDir, disableColor = []string{configPath}, nil, "", false
	preRun(mainCommand, nil)
	t.Setenv("INVOCATION_ID", "11111111111141118111111111111111")
	done := make(chan error, 1)
	go func() { done <- run() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("HY2 command did not stop")
			}
		}
		globalCtx, configPaths, configDirectories, workingDir, disableColor = oldCtx, oldPaths, oldDirectories, oldWorking, oldColor
	})
	proof := func(digest string) bool {
		data, err := os.ReadFile(configPath + ".runtime")
		var actual struct {
			ConfigDigest string `json:"config_digest"`
			PID          string `json:"pid"`
			Invocation   string `json:"invocation_id"`
		}
		return err == nil && json.Unmarshal(data, &actual) == nil && actual.ConfigDigest == digest && actual.PID == strconv.Itoa(os.Getpid()) && actual.Invocation == os.Getenv("INVOCATION_ID")
	}
	wait := func(ready func() bool) {
		deadline := time.Now().Add(3 * time.Second)
		for !ready() {
			select {
			case err := <-done:
				stopped = true
				t.Fatal("HY2 command exited before native proof", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("native proof was not confirmed")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait(func() bool { return proof(initialDigest) })
	inbound := document["inbounds"].([]any)[0].(map[string]any)
	inbound["users"] = []any{map[string]string{"name": "b", "password": "synthetic-b"}}
	nextDigest := write()
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return proof(nextDigest) })
	info, err := os.Stat(configPath + ".runtime")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("runtime proof permissions were not private")
	}
	// A changed listener cannot publish a proof for an unapplied candidate.
	inbound["listen_port"] = 1
	write()
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { _, err := os.Stat(configPath + ".runtime"); return os.IsNotExist(err) })
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("same process did not stop after the failed candidate")
	}
}

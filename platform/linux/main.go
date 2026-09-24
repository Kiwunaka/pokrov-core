//go:build linux

// The linuxd child has fixed runtime and metadata modes, no caller-controlled
// paths, profile arguments or listeners.
package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Kiwunaka/POKROV-core/v2/hcore"
	"github.com/Kiwunaka/POKROV-core/v2/linuxruntime"
	"github.com/sagernet/sing-box/experimental/libbox"
)

const (
	profilePath = "/var/lib/pokrov/profiles/active-profile.json"
	stateRoot   = "/var/lib/pokrov/core"
)

func main() {
	os.Exit(run())
}

func run() int {
	if os.Geteuid() != 0 {
		return 1
	}
	// Fixed metadata mode exits before opening a profile, state directory or
	// control pipe. It neither prepares nor starts a tunnel.
	if len(os.Args) == 2 && os.Args[1] == "--transport-capabilities" {
		metadata := struct {
			Schema       int    `json:"schema"`
			Capabilities string `json:"transport_capabilities_json"`
			ModuleSHA256 string `json:"core_module_sha256"`
		}{1, libbox.TransportCapabilities(), hcore.LinuxModuleSHA256(context.Background())}
		if json.NewEncoder(os.Stdout).Encode(metadata) != nil {
			return 1
		}
		return 0
	}
	if len(os.Args) != 1 {
		return 1
	}
	// The service's private control pipe is separate from all Core logging.
	replies := os.NewFile(3, "linuxd-core-control")
	if replies == nil {
		return 1
	}
	defer replies.Close()
	if info, err := replies.Stat(); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return 1
	}
	file, err := os.OpenFile(profilePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 1
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return 1
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return 1
	}
	profile, err := io.ReadAll(io.LimitReader(file, linuxruntime.MaximumConfigBytes+1))
	if err != nil || len(profile) > linuxruntime.MaximumConfigBytes {
		return 1
	}
	if err := os.MkdirAll(stateRoot+"/data", 0o700); err != nil {
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { <-ctx.Done(); _ = os.Stdin.Close() }()
	if err := hcore.ServeLinuxDaemon(ctx, profile, stateRoot, os.Stdin, replies); err != nil {
		return 1
	}
	return 0
}

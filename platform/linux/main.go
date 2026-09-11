//go:build linux

// The linuxd child has no caller-controlled arguments, paths or listeners.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Kiwunaka/POKROV-core/v2/hcore"
	"github.com/Kiwunaka/POKROV-core/v2/linuxruntime"
)

const (
	profilePath = "/var/lib/pokrov/profiles/active-profile.json"
	stateRoot   = "/var/lib/pokrov/core"
)

func main() {
	os.Exit(run())
}

func run() int {
	if os.Geteuid() != 0 || len(os.Args) != 1 {
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

//go:build linux

package main

import (
	"os"
	"syscall"
)

func hysteriaReloadSignal() os.Signal { return syscall.SIGUSR2 }

//go:build !windows

package slipstream

import "os/exec"

func hideWindow(*exec.Cmd) {}

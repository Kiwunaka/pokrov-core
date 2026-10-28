package slipstream

import (
	"os/exec"
	"syscall"
)

func hideWindow(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

package libbox

import (
	"errors"
	"runtime"

	"github.com/sagernet/sing-box/daemon"
)

func TelegramWSAdmissionVersion() int32 {
	if runtime.GOOS == "android" {
		return 1
	}
	return 0
}

// Pins and physical interface come from the trusted native host. Preparation
// authenticates the original signed table; it never admits WSS or starts it.
func PrepareTelegramWSProfile(configJSON, publicKeysJSON, audience, bindInterface string) (string, error) {
	if TelegramWSAdmissionVersion() != 1 {
		return "", errors.New("telegram_ws_platform_unavailable")
	}
	return daemon.PrepareTelegramWSProfile(configJSON, publicKeysJSON, audience, bindInterface, "android")
}

func (s *CommandServer) ReadTelegramWSAdmissionID(tag string) (string, error) {
	return s.StartedService.ReadTelegramWSAdmissionID(tag)
}

func (s *CommandServer) AdmitTelegramWSAdmission(id string) (bool, error) {
	return s.StartedService.AdmitTelegramWSAdmission(id)
}

func (s *CommandServer) WithdrawTelegramWSAdmission(id string) (bool, error) {
	return s.StartedService.WithdrawTelegramWSAdmission(id)
}

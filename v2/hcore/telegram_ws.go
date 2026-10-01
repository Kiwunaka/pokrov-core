package hcore

import (
	"errors"
	"runtime"

	"github.com/sagernet/sing-box/daemon"
)

func TelegramWSAdmissionVersion() int {
	if runtime.GOOS == "windows" {
		return 1
	}
	return 0
}

func PrepareWindowsTelegramWSProfile(configJSON, publicKeysJSON, audience, bindInterface string) (string, error) {
	if TelegramWSAdmissionVersion() != 1 {
		return "", errors.New("telegram_ws_platform_unavailable")
	}
	return daemon.PrepareTelegramWSProfile(configJSON, publicKeysJSON, audience, bindInterface, "windows")
}

func ReadTelegramWSAdmissionID(tag string) (string, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return "", errors.New("telegram_ws_runtime_unavailable")
	}
	return static.StartedService.ReadTelegramWSAdmissionID(tag)
}

func AdmitTelegramWSAdmission(id string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("telegram_ws_runtime_unavailable")
	}
	return static.StartedService.AdmitTelegramWSAdmission(id)
}

func WithdrawTelegramWSAdmission(id string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("telegram_ws_runtime_unavailable")
	}
	return static.StartedService.WithdrawTelegramWSAdmission(id)
}

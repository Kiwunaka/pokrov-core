package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

func hysteriaRuntimeProofPath(instance *box.Box) (string, error) {
	if instance.HysteriaRuntimeDigest() == "" {
		return "", nil
	}
	if hysteriaReloadSignal() == nil {
		return "", errors.New("hysteria_reload_platform_unsupported")
	}
	if len(configPaths) != 1 || len(configDirectories) != 0 || !filepath.IsAbs(configPaths[0]) {
		return "", errors.New("hysteria_reload_config_path_invalid")
	}
	return configPaths[0] + ".runtime", nil
}

func reloadHysteria(instance *box.Box) error {
	path, err := hysteriaRuntimeProofPath(instance)
	if err != nil {
		return err
	}
	if path == "" {
		return errors.New("hysteria_reload_disabled")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("hysteria_reload_proof_clear_failed")
	}
	entry, err := readConfigAt(configPaths[0])
	if err != nil {
		return errors.New("hysteria_reload_config_invalid")
	}
	if disableColor {
		if entry.options.Log == nil {
			entry.options.Log = &option.LogOptions{}
		}
		entry.options.Log.DisableColor = true
	}
	if err := instance.ReloadHysteria(entry.options); err != nil {
		return err
	}
	return writeHysteriaRuntimeProof(instance)
}

func writeHysteriaRuntimeProof(instance *box.Box) error {
	path, err := hysteriaRuntimeProofPath(instance)
	if err != nil || path == "" {
		return err
	}
	invocation := os.Getenv("INVOCATION_ID")
	decoded, err := hex.DecodeString(invocation)
	if err != nil || len(decoded) != 16 || invocation == strings.Repeat("0", 32) {
		return errors.New("hysteria_reload_invocation_unverified")
	}
	proof, err := json.Marshal(struct {
		ConfigDigest string `json:"config_digest"`
		PID          string `json:"pid"`
		InvocationID string `json:"invocation_id"`
	}{instance.HysteriaRuntimeDigest(), strconv.Itoa(os.Getpid()), invocation})
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".hysteria-runtime-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(proof); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

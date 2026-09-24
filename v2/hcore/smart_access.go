package hcore

import (
	"errors"
	"github.com/sagernet/sing-box/daemon"
)

func ConfigureSmartAccessRuntimeControl(profileDigest, configJSON string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("smart_access_runtime_unavailable")
	}
	return static.StartedService.ConfigureSmartAccessRuntimeControl(profileDigest, configJSON, sWorkingPath)
}

func ReadSmartAccessRestrictions() (string, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	return daemon.ReadSmartAccessRestrictions(sWorkingPath)
}

func ConfigureSmartAccessRenewal(profileDigest, configJSON string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("smart_access_runtime_unavailable")
	}
	return static.StartedService.ConfigureSmartAccessRenewal(profileDigest, configJSON)
}

func ReadSmartAccessLeases() (string, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return "", errors.New("smart_access_runtime_unavailable")
	}
	return static.StartedService.ReadSmartAccessLeases()
}

func AcknowledgeSmartAccessRestrictions(snapshotSHA256 string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	return daemon.AcknowledgeSmartAccessRestrictions(sWorkingPath, snapshotSHA256)
}

func RenewSmartAccessLease(expectedID, nextID, issuedAt, newFlowsUntil, activeFlowsUntil string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("smart_access_runtime_unavailable")
	}
	return static.StartedService.RenewSmartAccessLease(expectedID, nextID, issuedAt, newFlowsUntil, activeFlowsUntil)
}

func RevokeSmartAccessPolicy(terminateActive bool) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("smart_access_runtime_unavailable")
	}
	return static.StartedService.RevokeSmartAccessPolicy(terminateActive)
}

func RevokeSmartAccessLease(leaseID string, terminateActive bool) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("smart_access_runtime_unavailable")
	}
	return static.StartedService.RevokeSmartAccessLease(leaseID, terminateActive)
}

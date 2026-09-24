package hcore

import "errors"

func ConfirmATSLease(leaseID, issuedAt, newFlowsUntil,
	activeFlowsUntil string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("ats_endpoint_lease_unavailable")
	}
	return static.StartedService.ConfirmATSLease(leaseID, issuedAt, newFlowsUntil, activeFlowsUntil)
}

func RevokeATSLease(leaseID string, terminateActive bool) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("ats_endpoint_lease_unavailable")
	}
	return static.StartedService.RevokeATSLease(leaseID, terminateActive)
}

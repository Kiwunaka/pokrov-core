package libbox

import "github.com/sagernet/sing-box/daemon"

// Version 1 covers visible-SNI TCP/443, fixed relay, quota/lifetime enforcement
// and exact-lease revocation. It does not assert provider or device readiness.
func SmartAccessLeaseVersion() int32 { return 1 }

// Separate negotiation: source support does not assert loaded host provisioning.
func SmartAccessRuntimeControlVersion() int32 { return 1 }

func (s *CommandServer) ReadSmartAccessLeases() (string, error) {
	return s.StartedService.ReadSmartAccessLeases()
}

func (s *CommandServer) ConfigureSmartAccessRuntimeControl(profileDigest, configJSON string) (bool, error) {
	return s.StartedService.ConfigureSmartAccessRuntimeControl(profileDigest, configJSON, sWorkingPath)
}

func (s *CommandServer) ConfigureSmartAccessRenewal(profileDigest, configJSON string) (bool, error) {
	return s.StartedService.ConfigureSmartAccessRenewal(profileDigest, configJSON)
}

func ReadSmartAccessRestrictions() (string, error) {
	return daemon.ReadSmartAccessRestrictions(sWorkingPath)
}

func AcknowledgeSmartAccessRestrictions(snapshotSHA256 string) (bool, error) {
	return daemon.AcknowledgeSmartAccessRestrictions(sWorkingPath, snapshotSHA256)
}

func (s *CommandServer) RenewSmartAccessLease(expectedID, nextID, issuedAt, newFlowsUntil, activeFlowsUntil string) (bool, error) {
	return s.StartedService.RenewSmartAccessLease(expectedID, nextID, issuedAt, newFlowsUntil, activeFlowsUntil)
}

func (s *CommandServer) RevokeSmartAccessPolicy(terminateActive bool) (bool, error) {
	return s.StartedService.RevokeSmartAccessPolicy(terminateActive)
}

func (s *CommandServer) RevokeSmartAccessLease(leaseID string, terminateActive bool) (bool, error) {
	return s.StartedService.RevokeSmartAccessLease(leaseID, terminateActive)
}

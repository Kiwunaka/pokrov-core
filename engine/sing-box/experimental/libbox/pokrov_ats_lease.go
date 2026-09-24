package libbox

func (s *CommandServer) ConfirmATSLease(leaseID, issuedAt, newFlowsUntil,
	activeFlowsUntil string) (bool, error) {
	return s.StartedService.ConfirmATSLease(leaseID, issuedAt, newFlowsUntil, activeFlowsUntil)
}

func (s *CommandServer) RevokeATSLease(leaseID string, terminateActive bool) (bool, error) {
	return s.StartedService.RevokeATSLease(leaseID, terminateActive)
}

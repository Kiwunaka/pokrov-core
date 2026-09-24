package daemon

import (
	"errors"
	"regexp"

	"github.com/sagernet/sing-box/protocol/pokrov/atslease"
)

var atsLeaseID = regexp.MustCompile(`^lease_[a-f0-9]{32}$`)

func (s *StartedService) ConfirmATSLease(leaseID, issuedAt, newFlowsUntil,
	activeFlowsUntil string) (bool, error) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return false, errors.New("ats_endpoint_lease_unavailable")
	}
	outbound, found := s.instance.instance.Outbound().Outbound("pokrov-ats")
	if !found { return false, nil }
	lease, ok := outbound.(*atslease.Outbound)
	return ok && lease.ConfirmLease(leaseID, issuedAt, newFlowsUntil, activeFlowsUntil), nil
}

func (s *StartedService) RevokeATSLease(leaseID string, terminateActive bool) (bool, error) {
	if !atsLeaseID.MatchString(leaseID) { return false, errors.New("ats_endpoint_lease_invalid") }
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return false, errors.New("ats_endpoint_lease_unavailable")
	}
	outbound, found := s.instance.instance.Outbound().Outbound("pokrov-ats")
	if !found { return false, nil }
	lease, ok := outbound.(*atslease.Outbound)
	return ok && lease.RevokeLease(leaseID, terminateActive), nil
}

package daemon

import (
	"errors"
	"regexp"

	"github.com/sagernet/sing-box/protocol/pokrov/smartaccess"
)

var routingCatalogServiceID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func (s *StartedService) RevokeRoutingCatalogService(serviceID string) (bool, error) {
	if !routingCatalogServiceID.MatchString(serviceID) { return false, errors.New("catalog_service_invalid") }
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return false, errors.New("catalog_runtime_unavailable")
	}
	return s.instance.instance.RevokeRoutingCatalogService(serviceID), nil
}

// A whole-catalog withdrawal closes leased provider flows as well as removing
// catalog rule admission. It is not a transport-error or refresh-expiry action.
func (s *StartedService) RevokeRoutingCatalog() (bool, error) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return false, errors.New("catalog_runtime_unavailable")
	}
	instance := s.instance.instance
	found := instance.RevokeRoutingCatalog()
	for _, outbound := range instance.Outbound().Outbounds() {
		if lease, ok := outbound.(*smartaccess.Outbound); ok {
			lease.Revoke(true)
			found = true
		}
	}
	return found, nil
}

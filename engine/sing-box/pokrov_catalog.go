package box

func (s *Box) RevokeRoutingCatalogService(serviceID string) bool {
	found := s.dnsRouter.RevokeRoutingCatalogService(serviceID)
	for _, rule := range s.router.Rules() {
		if revoker, ok := rule.(interface { RevokeRoutingCatalogService(string) bool }); ok {
			if revoker.RevokeRoutingCatalogService(serviceID) { found = true }
		}
	}
	return found
}

// The host authenticates the withdrawal and fences the exact running profile.
// Timed catalog rules stop admitting new decisions; untimed fallback rules and
// already routed non-lease connections are left in place.
func (s *Box) RevokeRoutingCatalog() bool {
	found := s.dnsRouter.RevokeRoutingCatalog()
	for _, rule := range s.router.Rules() {
		if revoker, ok := rule.(interface { RevokeRoutingCatalog() bool }); ok {
			if revoker.RevokeRoutingCatalog() { found = true }
		}
	}
	return found
}

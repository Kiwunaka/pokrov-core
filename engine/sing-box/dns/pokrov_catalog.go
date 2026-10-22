package dns

func (r *Router) RevokeRoutingCatalogService(serviceID string) bool {
	r.rulesAccess.RLock()
	rules := r.rules
	r.rulesAccess.RUnlock()
	found := false
	for _, rule := range rules {
		if revoker, ok := rule.(interface{ RevokeRoutingCatalogService(string) bool }); ok {
			if revoker.RevokeRoutingCatalogService(serviceID) {
				found = true
			}
		}
	}
	return found
}

// RevokeRoutingCatalog affects subsequent DNS rule selection. Already admitted
// exchanges and application-owned caches are not cancelled by this gate.
func (r *Router) RevokeRoutingCatalog() bool {
	r.rulesAccess.RLock()
	rules := r.rules
	r.rulesAccess.RUnlock()
	found := false
	for _, rule := range rules {
		if revoker, ok := rule.(interface{ RevokeRoutingCatalog() bool }); ok {
			if revoker.RevokeRoutingCatalog() {
				found = true
			}
		}
	}
	return found
}

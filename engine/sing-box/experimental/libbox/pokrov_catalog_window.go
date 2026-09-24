package libbox

// RoutingCatalogWindowVersion describes parser/matcher support in this binary.
// It is not a device, DNS-visibility or installed-artifact readiness assertion.
func RoutingCatalogWindowVersion() int32 {
	return 1
}

// Separate from lifetime support: old binaries can expire catalog rules but
// cannot accept a received whole-catalog withdrawal.
// Version 4 adds same-scope lease renewal; window admission still consults the
// current lease and cannot exceed the original catalog window.
func RoutingCatalogControlVersion() int32 { return 4 }

func (s *CommandServer) RevokeRoutingCatalogService(serviceID string) (bool, error) {
	return s.StartedService.RevokeRoutingCatalogService(serviceID)
}

func (s *CommandServer) RevokeRoutingCatalog() (bool, error) {
	return s.StartedService.RevokeRoutingCatalog()
}

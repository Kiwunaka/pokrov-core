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

// LocalDpiAdmissionVersion reports API support only, not signed proof or
// caller/device readiness.
func LocalDpiAdmissionVersion() int32 { return 1 }

func (s *CommandServer) ReadLocalDpiAdmissionID(outboundTag string) (string, error) {
	return s.StartedService.ReadLocalDpiAdmissionID(outboundTag)
}

func (s *CommandServer) AdmitLocalDpiAdmission(admissionID string) (bool, error) {
	return s.StartedService.AdmitLocalDpiAdmission(admissionID)
}

func (s *CommandServer) WithdrawLocalDpiAdmission(admissionID string) (bool, error) {
	return s.StartedService.WithdrawLocalDpiAdmission(admissionID)
}

func (s *CommandServer) RevokeRoutingCatalogService(serviceID string) (bool, error) {
	return s.StartedService.RevokeRoutingCatalogService(serviceID)
}

func (s *CommandServer) RevokeRoutingCatalog() (bool, error) {
	return s.StartedService.RevokeRoutingCatalog()
}

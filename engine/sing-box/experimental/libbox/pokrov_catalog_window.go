package libbox

import "github.com/sagernet/sing-box/daemon"

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

// VerifyLocalDpiCatalog authenticates the original catalog bytes and the
// requested Android Selective scope. Keys must come from the native host's
// compiled pins; this does not publish admission or perform the TLS proof.
func VerifyLocalDpiCatalog(envelopeJSON, publicKeysJSON, audience, expectedPayloadSHA256 string,
	expectedRevision, expectedSecurityRevision int64, serviceID, controlHost, accessState string) bool {
	return daemon.VerifyLocalDpiCatalog(envelopeJSON, publicKeysJSON, audience, expectedPayloadSHA256,
		expectedRevision, expectedSecurityRevision, serviceID, controlHost, accessState)
}

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

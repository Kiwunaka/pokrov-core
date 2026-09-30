package hcore

import "errors"

func ReadLocalDpiAdmissionID(outboundTag string) (string, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return "", errors.New("local_dpi_runtime_unavailable")
	}
	return static.StartedService.ReadLocalDpiAdmissionID(outboundTag)
}

func AdmitLocalDpiAdmission(admissionID string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("local_dpi_runtime_unavailable")
	}
	return static.StartedService.AdmitLocalDpiAdmission(admissionID)
}

func WithdrawLocalDpiAdmission(admissionID string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("local_dpi_runtime_unavailable")
	}
	return static.StartedService.WithdrawLocalDpiAdmission(admissionID)
}

func RevokeRoutingCatalogService(serviceID string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("catalog_runtime_unavailable")
	}
	return static.StartedService.RevokeRoutingCatalogService(serviceID)
}

func RevokeRoutingCatalog() (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("catalog_runtime_unavailable")
	}
	return static.StartedService.RevokeRoutingCatalog()
}
